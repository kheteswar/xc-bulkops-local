// =============================================================================
// Live SOC Monitoring Room — Anomaly Detection Engine
// =============================================================================
// Implements all 23 anomaly detectors from spec Section 9.2:
//   1. RPS Spike          2. RPS Drop           3. 5xx Error Spike
//   4. 4xx Error Spike    5. WAF Surge          6. New Signature
//   7. Latency Spike      8. Origin Down        9. Geo Anomaly
//  10. Bot Surge (AL)    11. Rate Limit Fire   12. Threat Mesh New IP
//  13. CDN Cache Degrad. 14. Config Change     15. Sample Rate Surge
//  16. Bot Traffic (BD)  17. Credential Stuff. 18. Synthetic Monitor Fail
//  19. DNS Health Degrad 20. Client-Side Script 21. WAF Sig Update
//  22. Network DDoS Alert 23. API Vulnerability
//
// Also provides:
//   - updateBaseline: EMA-based rolling baseline update
//   - computeThreatLevel: from anomalies, alerts, incidents
// =============================================================================

import type {
  DashboardMetrics,
  LatencyStats,
  Baseline,
  SOCRoomConfig,
  BotTrafficOverview,
  SyntheticHealthSummary,
  DNSHealthStatus,
  AlertEntry,
  Anomaly,
  AnomalySeverity,
  DetectorId,
  Incident,
  ThreatLevel,
} from './types';

// =============================================================================
// ID Generation
// =============================================================================

function generateAnomalyId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

// =============================================================================
// Detector Helpers
// =============================================================================

function createAnomaly(
  detectorId: DetectorId,
  detectorName: string,
  severity: AnomalySeverity,
  triggerValue: number | string,
  baselineValue: number | string,
  message: string
): Anomaly {
  const now = new Date().toISOString();
  return {
    id: generateAnomalyId(),
    detectorId,
    detectorName,
    severity,
    triggerValue,
    baselineValue,
    message,
    firstDetectedAt: now,
    lastDetectedAt: now,
    resolved: false,
  };
}

// =============================================================================
// Individual Detectors (1-23)
// =============================================================================

// Detector 1: RPS Spike (> avg + 3 sigma)
function detectRpsSpike(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  const threshold = baseline.avgRps + 3 * baseline.stdDevRps;
  if (threshold <= 0) return null;

  if (metrics.rps > threshold) {
    const severity: AnomalySeverity =
      metrics.totalSecEvents > baseline.avgSecEvents * 2 ? 'HIGH' : 'MEDIUM';
    return createAnomaly(
      1, 'RPS Spike', severity,
      Math.round(metrics.rps),
      `avg=${Math.round(baseline.avgRps)} +3σ=${Math.round(threshold)}`,
      `RPS spiked to ${Math.round(metrics.rps)} (baseline avg ${Math.round(baseline.avgRps)}, threshold ${Math.round(threshold)})`
    );
  }
  return null;
}

// Detector 2: RPS Drop (< avg - 3 sigma)
function detectRpsDrop(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (baseline.avgRps < 1) return null; // No meaningful baseline yet

  const threshold = Math.max(0, baseline.avgRps - 3 * baseline.stdDevRps);
  if (metrics.rps < threshold) {
    return createAnomaly(
      2, 'RPS Drop', 'HIGH',
      Math.round(metrics.rps),
      `avg=${Math.round(baseline.avgRps)} -3σ=${Math.round(threshold)}`,
      `RPS dropped to ${Math.round(metrics.rps)} (baseline avg ${Math.round(baseline.avgRps)}, threshold ${Math.round(threshold)})`
    );
  }
  return null;
}

// Detector 3: 5xx Error Spike (> 2x baseline)
function detect5xxSpike(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  const baseVal = baseline.avg5xxRate;

  // Minimum threshold: at least 1% baseline or absolute minimum
  if (baseVal < 0.001 && metrics.error5xxRate < 0.01) return null;

  const threshold = Math.max(baseVal * 2, 0.01);
  if (metrics.error5xxRate > threshold) {
    const severity: AnomalySeverity =
      metrics.error5xxRate > 0.1 ? 'CRITICAL' : 'HIGH';
    return createAnomaly(
      3, '5xx Error Spike', severity,
      `${(metrics.error5xxRate * 100).toFixed(1)}%`,
      `${(baseVal * 100).toFixed(1)}% (2x=${(threshold * 100).toFixed(1)}%)`,
      `5xx error rate at ${(metrics.error5xxRate * 100).toFixed(1)}% (baseline ${(baseVal * 100).toFixed(1)}%, threshold ${(threshold * 100).toFixed(1)}%)`
    );
  }
  return null;
}

// Detector 4: 4xx Error Spike (> 3x baseline)
function detect4xxSpike(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  const baseVal = baseline.avg4xxRate;

  if (baseVal < 0.001 && metrics.error4xxRate < 0.05) return null;

  const threshold = Math.max(baseVal * 3, 0.05);
  if (metrics.error4xxRate > threshold) {
    return createAnomaly(
      4, '4xx Error Spike', 'MEDIUM',
      `${(metrics.error4xxRate * 100).toFixed(1)}%`,
      `${(baseVal * 100).toFixed(1)}% (3x=${(threshold * 100).toFixed(1)}%)`,
      `4xx error rate at ${(metrics.error4xxRate * 100).toFixed(1)}% (baseline ${(baseVal * 100).toFixed(1)}%, threshold ${(threshold * 100).toFixed(1)}%)`
    );
  }
  return null;
}

// Detector 5: WAF Surge (> 3x baseline)
function detectWafSurge(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (baseline.avgSecEvents < 1 && metrics.totalSecEvents < 5) return null;

  const threshold = Math.max(baseline.avgSecEvents * 3, 5);
  if (metrics.totalSecEvents > threshold) {
    return createAnomaly(
      5, 'WAF Surge', 'HIGH',
      metrics.totalSecEvents,
      `avg=${Math.round(baseline.avgSecEvents)} (3x=${Math.round(threshold)})`,
      `Security events surged to ${metrics.totalSecEvents} (baseline avg ${Math.round(baseline.avgSecEvents)}, threshold ${Math.round(threshold)})`
    );
  }
  return null;
}

// Detector 6: New Signature (ID not in baseline known set)
function detectNewSignature(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  const knownIds = new Set(baseline.knownSignatureIds);
  if (knownIds.size === 0) return null;

  const newSigs: string[] = [];
  for (const sig of metrics.topSignatures) {
    if (!knownIds.has(sig.id) && sig.count > 0) {
      newSigs.push(sig.id);
    }
  }

  if (newSigs.length > 0) {
    return createAnomaly(
      6, 'New Signature', 'MEDIUM',
      newSigs.join(', '),
      `${knownIds.size} known signatures`,
      `${newSigs.length} new WAF signature(s) detected: ${newSigs.slice(0, 5).join(', ')}${newSigs.length > 5 ? '...' : ''}`
    );
  }
  return null;
}

// Detector 7: Latency Spike (P95 > 3x baseline)
function detectLatencySpike(
  latencyStats: LatencyStats,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (baseline.avgLatencyP95 <= 0) return null;

  const threshold = baseline.avgLatencyP95 * 3;
  if (latencyStats.p95 > threshold && latencyStats.p95 > 100) {
    return createAnomaly(
      7, 'Latency Spike', 'HIGH',
      `${Math.round(latencyStats.p95)}ms`,
      `avg_p95=${Math.round(baseline.avgLatencyP95)}ms (3x=${Math.round(threshold)}ms)`,
      `P95 latency spiked to ${Math.round(latencyStats.p95)}ms (baseline P95 avg ${Math.round(baseline.avgLatencyP95)}ms, threshold ${Math.round(threshold)}ms)`
    );
  }
  return null;
}

// Detector 8: Origin Down (no_healthy_upstream in error diagnosis)
function detectOriginDown(
  metrics: DashboardMetrics
): Anomaly | null {
  const noHealthy = metrics.errorDiagnosis.find(
    (d) => d.rspCodeDetails.includes('no_healthy_upstream')
  );

  if (noHealthy && noHealthy.count > 0) {
    return createAnomaly(
      8, 'Origin Down', 'CRITICAL',
      noHealthy.count,
      '0 (no_healthy_upstream should be 0)',
      `Origin down: ${noHealthy.count} requests returned no_healthy_upstream — all health checks failing`
    );
  }
  return null;
}

// Detector 9: Geo Anomaly (new country > 5%)
function detectGeoAnomaly(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  const knownCountries = new Set(Object.keys(baseline.topCountries));
  if (knownCountries.size === 0) return null;

  const newCountries: Array<{ country: string; pct: number }> = [];
  for (const geo of metrics.geoDistribution) {
    if (!knownCountries.has(geo.country) && geo.pct > 5) {
      newCountries.push({ country: geo.country, pct: geo.pct });
    }
  }

  if (newCountries.length > 0) {
    const desc = newCountries
      .map((c) => `${c.country} (${c.pct.toFixed(1)}%)`)
      .join(', ');
    return createAnomaly(
      9, 'Geo Anomaly', 'MEDIUM',
      desc,
      `${knownCountries.size} known countries`,
      `New traffic source(s) with significant volume: ${desc}`
    );
  }
  return null;
}

// Detector 10: Bot Surge from access logs (bot ratio > 2x)
function detectBotSurgeFromLogs(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (metrics.botRatio === null) return null;
  if (baseline.avgBotRatio <= 0 && metrics.botRatio < 0.1) return null;

  const threshold = Math.max(baseline.avgBotRatio * 2, 0.1);
  if (metrics.botRatio > threshold) {
    return createAnomaly(
      10, 'Bot Surge (Access Logs)', 'HIGH',
      `${(metrics.botRatio * 100).toFixed(1)}%`,
      `avg=${(baseline.avgBotRatio * 100).toFixed(1)}% (2x=${(threshold * 100).toFixed(1)}%)`,
      `Bot traffic ratio surged to ${(metrics.botRatio * 100).toFixed(1)}% (baseline ${(baseline.avgBotRatio * 100).toFixed(1)}%)`
    );
  }
  return null;
}

// Detector 11: Rate Limit Fire (from wafActions containing rate_limiter)
function detectRateLimitFire(
  metrics: DashboardMetrics
): Anomaly | null {
  const rateLimitActions = metrics.wafActions.filter(
    (a) => a.action.toLowerCase().includes('rate_limit')
  );

  const totalRateLimited = rateLimitActions.reduce((sum, a) => sum + a.count, 0);
  if (totalRateLimited > 0) {
    return createAnomaly(
      11, 'Rate Limit Fire', 'MEDIUM',
      totalRateLimited,
      '0 (no rate limiting expected)',
      `Rate limiter triggered on ${totalRateLimited} requests`
    );
  }
  return null;
}

// Detector 12: Threat Mesh New IP (tenant_count >= 5 from sec events)
function detectThreatMeshNewIp(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (baseline.avgThreatMeshHits < 1 && metrics.topAttackingIps.length < 5) return null;

  // Check if attacking IP count exceeds baseline significantly
  const currentAttackIps = metrics.topAttackingIps.length;
  const threshold = Math.max(baseline.avgThreatMeshHits * 2, 5);

  if (currentAttackIps >= threshold) {
    return createAnomaly(
      12, 'Threat Mesh New IP', 'HIGH',
      currentAttackIps,
      `avg=${Math.round(baseline.avgThreatMeshHits)} (threshold=${Math.round(threshold)})`,
      `${currentAttackIps} attacking IPs detected (exceeds threat mesh threshold of ${Math.round(threshold)})`
    );
  }
  return null;
}

// Detector 13: CDN Cache Degradation (hit ratio drop > 15pt)
function detectCdnCacheDegradation(
  metrics: DashboardMetrics,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (metrics.cacheHitRatio === null) return null;
  if (baseline.avgCacheHitRatio <= 0) return null;

  const drop = baseline.avgCacheHitRatio - metrics.cacheHitRatio;
  if (drop > 0.15) {
    return createAnomaly(
      13, 'CDN Cache Degradation', 'HIGH',
      `${(metrics.cacheHitRatio * 100).toFixed(1)}%`,
      `avg=${(baseline.avgCacheHitRatio * 100).toFixed(1)}% (drop=${(drop * 100).toFixed(1)}pt)`,
      `CDN cache hit ratio dropped to ${(metrics.cacheHitRatio * 100).toFixed(1)}% from baseline ${(baseline.avgCacheHitRatio * 100).toFixed(1)}% (${(drop * 100).toFixed(1)}pt drop)`
    );
  }
  return null;
}

// Detector 14: Config Change (any audit entry)
function detectConfigChange(
  metrics: DashboardMetrics
): Anomaly | null {
  if (metrics.recentConfigChanges > 0) {
    return createAnomaly(
      14, 'Config Change', 'INFO',
      metrics.recentConfigChanges,
      '0 (no changes expected)',
      `${metrics.recentConfigChanges} configuration change(s) detected in monitoring window`
    );
  }
  return null;
}

// Detector 15: Sample Rate Surge (> 5x increase)
function detectSampleRateSurge(
  currentSampleRate: number,
  baseline: Baseline
): Anomaly | null {
  if (baseline.sampleCount < 3) return null;
  if (baseline.avgSampleRate <= 0) return null;

  const ratio = currentSampleRate / baseline.avgSampleRate;
  if (ratio > 5) {
    return createAnomaly(
      15, 'Sample Rate Surge', 'MEDIUM',
      `${currentSampleRate.toFixed(1)}x`,
      `avg=${baseline.avgSampleRate.toFixed(1)}x (5x threshold)`,
      `Sample rate surged to ${currentSampleRate.toFixed(1)}x (baseline ${baseline.avgSampleRate.toFixed(1)}x) — F5 XC is under heavy load`
    );
  }
  return null;
}

// Detector 16: Bot Traffic Surge from Bot Defense (malicious % > 2x)
function detectBotDefenseSurge(
  botOverview: BotTrafficOverview | null,
  baseline: Baseline
): Anomaly | null {
  if (!botOverview) return null;
  if (baseline.sampleCount < 3) return null;

  const maliciousPct = botOverview.maliciousBotPct;
  if (baseline.avgBotRatio <= 0 && maliciousPct < 5) return null;

  const threshold = Math.max(baseline.avgBotRatio * 2, 5);
  if (maliciousPct > threshold) {
    return createAnomaly(
      16, 'Bot Traffic Surge (Bot Defense)', 'HIGH',
      `${maliciousPct.toFixed(1)}%`,
      `avg=${baseline.avgBotRatio.toFixed(1)}% (2x=${threshold.toFixed(1)}%)`,
      `Malicious bot traffic at ${maliciousPct.toFixed(1)}% (baseline ${baseline.avgBotRatio.toFixed(1)}%, threshold ${threshold.toFixed(1)}%)`
    );
  }
  return null;
}

// Detector 17: Credential Stuffing detected
function detectCredentialStuffing(
  botOverview: BotTrafficOverview | null
): Anomaly | null {
  if (!botOverview) return null;

  if (botOverview.credentialStuffingDetected) {
    return createAnomaly(
      17, 'Credential Stuffing', 'CRITICAL',
      'detected',
      'not_detected',
      'Credential stuffing attack detected by Bot Defense'
    );
  }
  return null;
}

// Detector 18: Synthetic Monitor Fail
function detectSyntheticMonitorFail(
  syntheticHealth: SyntheticHealthSummary | null
): Anomaly | null {
  if (!syntheticHealth) return null;

  const failingMonitors = syntheticHealth.monitors.filter(
    (m) => m.status === 'unhealthy'
  );

  if (failingMonitors.length > 0) {
    const names = failingMonitors.map((m) => m.name).join(', ');
    return createAnomaly(
      18, 'Synthetic Monitor Fail', 'CRITICAL',
      `${failingMonitors.length} failing`,
      '0 failing monitors',
      `${failingMonitors.length} synthetic monitor(s) failing: ${names}`
    );
  }
  return null;
}

// Detector 19: DNS Health Degradation
function detectDnsHealthDegradation(
  dnsHealth: DNSHealthStatus | null
): Anomaly | null {
  if (!dnsHealth) return null;

  const degradedLbs = dnsHealth.loadBalancers.filter(
    (lb) => lb.status === 'degraded' || lb.status === 'down'
  );

  if (degradedLbs.length > 0) {
    const names = degradedLbs.map((lb) => `${lb.name} (${lb.status})`).join(', ');
    const severity: AnomalySeverity = degradedLbs.some((lb) => lb.status === 'down')
      ? 'CRITICAL'
      : 'HIGH';
    return createAnomaly(
      19, 'DNS Health Degradation', severity,
      `${degradedLbs.length} degraded`,
      '0 (all healthy)',
      `DNS health degraded: ${names}`
    );
  }
  return null;
}

// Detector 20: Client-Side Script Alert (from CSD)
function detectClientSideScriptAlert(
  metrics: DashboardMetrics
): Anomaly | null {
  // CSD data is surfaced through the investigation engine when csdSummary
  // is available. The detector checks for the presence of CSD-related
  // security events in the security breakdown.
  const csdEvents = metrics.securityBreakdown.filter(
    (s) => s.eventName.toLowerCase().includes('csd') ||
           s.eventName.toLowerCase().includes('client_side') ||
           s.eventName.toLowerCase().includes('magecart')
  );

  const totalCsd = csdEvents.reduce((sum, e) => sum + e.count, 0);
  if (totalCsd > 0) {
    return createAnomaly(
      20, 'Client-Side Script Alert', 'CRITICAL',
      totalCsd,
      '0 (no CSD events)',
      `${totalCsd} client-side defense event(s) detected — possible malicious script injection`
    );
  }
  return null;
}

// Detector 21: WAF Signature Update (from changelog)
function detectWafSignatureUpdate(
  alerts: AlertEntry[]
): Anomaly | null {
  const sigAlerts = alerts.filter(
    (a) => a.type.toLowerCase().includes('signature') ||
           a.name.toLowerCase().includes('signature_update') ||
           a.description.toLowerCase().includes('signature')
  );

  if (sigAlerts.length > 0) {
    return createAnomaly(
      21, 'WAF Signature Update', 'INFO',
      sigAlerts.length,
      '0',
      `${sigAlerts.length} WAF signature update(s) detected — monitor for false positive changes`
    );
  }
  return null;
}

// Detector 22: Network DDoS Alert (from InfraProtect)
function detectNetworkDdosAlert(
  alerts: AlertEntry[]
): Anomaly | null {
  const ddosAlerts = alerts.filter(
    (a) => a.type.toLowerCase().includes('ddos') ||
           a.type.toLowerCase().includes('infraprotect') ||
           a.name.toLowerCase().includes('ddos')
  );

  if (ddosAlerts.length > 0) {
    const severity: AnomalySeverity = ddosAlerts.some(
      (a) => a.severity === 'critical'
    )
      ? 'CRITICAL'
      : 'HIGH';
    return createAnomaly(
      22, 'Network DDoS Alert', severity,
      ddosAlerts.length,
      '0 (no DDoS alerts)',
      `${ddosAlerts.length} network-layer DDoS alert(s) active`
    );
  }
  return null;
}

// Detector 23: API Vulnerability
function detectApiVulnerability(
  alerts: AlertEntry[]
): Anomaly | null {
  const vulnAlerts = alerts.filter(
    (a) => a.type.toLowerCase().includes('vulnerability') ||
           a.type.toLowerCase().includes('api_security') ||
           a.name.toLowerCase().includes('vulnerability')
  );

  if (vulnAlerts.length > 0) {
    return createAnomaly(
      23, 'API Vulnerability', 'HIGH',
      vulnAlerts.length,
      '0',
      `${vulnAlerts.length} API vulnerability alert(s) detected`
    );
  }
  return null;
}

// =============================================================================
// Main Evaluator
// =============================================================================

/**
 * Runs all 23 anomaly detectors and returns the list of detected anomalies.
 *
 * @param metrics - Current cycle's dashboard metrics
 * @param latencyStats - Current cycle's latency stats from Track 3
 * @param baseline - Learned baseline for comparison
 * @param room - Room configuration (for feature flags)
 * @param botOverview - Bot Defense data (null if not enabled)
 * @param syntheticHealth - Synthetic monitoring data (null if not enabled)
 * @param dnsHealth - DNS health data (null if no DNS LBs configured)
 * @param alerts - Current active alerts
 * @param sampleRate - Current raw log sample rate
 */
export function evaluateDetectors(
  metrics: DashboardMetrics,
  latencyStats: LatencyStats,
  baseline: Baseline,
  room: SOCRoomConfig,
  botOverview: BotTrafficOverview | null,
  syntheticHealth: SyntheticHealthSummary | null,
  dnsHealth: DNSHealthStatus | null,
  alerts: AlertEntry[],
  sampleRate: number
): Anomaly[] {
  const anomalies: Anomaly[] = [];

  // Helper to add non-null anomalies
  const check = (result: Anomaly | null) => {
    if (result) anomalies.push(result);
  };

  // Core traffic detectors (1-4)
  check(detectRpsSpike(metrics, baseline));
  check(detectRpsDrop(metrics, baseline));
  check(detect5xxSpike(metrics, baseline));
  check(detect4xxSpike(metrics, baseline));

  // Security detectors (5-6)
  check(detectWafSurge(metrics, baseline));
  check(detectNewSignature(metrics, baseline));

  // Performance detector (7)
  check(detectLatencySpike(latencyStats, baseline));

  // Origin detector (8)
  check(detectOriginDown(metrics));

  // Geo detector (9)
  check(detectGeoAnomaly(metrics, baseline));

  // Bot detector from access logs (10)
  check(detectBotSurgeFromLogs(metrics, baseline));

  // Rate limit detector (11)
  check(detectRateLimitFire(metrics));

  // Threat Mesh detector (12)
  check(detectThreatMeshNewIp(metrics, baseline));

  // CDN detector (13)
  check(detectCdnCacheDegradation(metrics, baseline));

  // Config change detector (14)
  check(detectConfigChange(metrics));

  // Sample rate detector (15)
  check(detectSampleRateSurge(sampleRate, baseline));

  // Bot Defense detectors (16-17) — conditional on feature flag
  if (room.features.botDefenseEnabled) {
    check(detectBotDefenseSurge(botOverview, baseline));
    check(detectCredentialStuffing(botOverview));
  }

  // Synthetic monitor detector (18) — conditional
  if (room.features.syntheticMonitorsEnabled) {
    check(detectSyntheticMonitorFail(syntheticHealth));
  }

  // DNS health detector (19) — conditional
  if (room.dnsLoadBalancers.length > 0) {
    check(detectDnsHealthDegradation(dnsHealth));
  }

  // CSD detector (20) — conditional
  if (room.features.clientSideDefenseEnabled) {
    check(detectClientSideScriptAlert(metrics));
  }

  // WAF signature update detector (21)
  check(detectWafSignatureUpdate(alerts));

  // Network DDoS detector (22) — conditional
  if (room.features.infraProtectEnabled) {
    check(detectNetworkDdosAlert(alerts));
  }

  // API vulnerability detector (23) — conditional
  if (room.features.apiSecurityEnabled) {
    check(detectApiVulnerability(alerts));
  }

  return anomalies;
}

// =============================================================================
// Baseline Update
// =============================================================================

/**
 * Updates the rolling baseline using exponential moving average (EMA).
 * Alpha = 2 / (sampleCount + 1), giving more weight to recent observations
 * while gradually building a stable baseline over many cycles.
 *
 * @param metrics - Current cycle's dashboard metrics
 * @param latencyStats - Current cycle's latency stats
 * @param baseline - Previous baseline to update
 * @returns Updated baseline
 */
export function updateBaseline(
  metrics: DashboardMetrics,
  latencyStats: LatencyStats,
  baseline: Baseline,
  sampleRate: number = 1
): Baseline {
  const n = baseline.sampleCount + 1;
  const alpha = 2 / (n + 1);

  // EMA helper
  const ema = (prev: number, current: number): number =>
    alpha * current + (1 - alpha) * prev;

  // Update RPS with standard deviation tracking
  const newAvgRps = ema(baseline.avgRps, metrics.rps);
  // Welford's online algorithm for variance
  const diff = metrics.rps - baseline.avgRps;
  const newDiff = metrics.rps - newAvgRps;
  const variance =
    baseline.sampleCount > 0
      ? (baseline.stdDevRps ** 2 * (baseline.sampleCount - 1) + diff * newDiff) / n
      : 0;
  const newStdDevRps = Math.sqrt(Math.max(0, variance));

  // Update error rates
  const newAvgErrorRate = ema(baseline.avgErrorRate, metrics.errorRate);
  const newAvg5xxRate = ema(baseline.avg5xxRate, metrics.error5xxRate);
  const newAvg4xxRate = ema(baseline.avg4xxRate, metrics.error4xxRate);

  // Update security metrics
  const newAvgSecEvents = ema(baseline.avgSecEvents, metrics.totalSecEvents);

  // WAF blocks: sum of wafActions with 'block' in the action
  const wafBlocks = metrics.wafActions
    .filter((a) => a.action.toLowerCase().includes('block'))
    .reduce((sum, a) => sum + a.count, 0);
  const newAvgWafBlocks = ema(baseline.avgWafBlocks, wafBlocks);

  // Threat mesh hits (from attacking IP count as proxy)
  const newAvgThreatMeshHits = ema(
    baseline.avgThreatMeshHits,
    metrics.topAttackingIps.length
  );

  // Bot ratio
  const newAvgBotRatio = ema(
    baseline.avgBotRatio,
    metrics.botRatio ?? baseline.avgBotRatio
  );

  // Known signature IDs — union with current
  const knownSigs = new Set(baseline.knownSignatureIds);
  for (const sig of metrics.topSignatures) {
    if (sig.id) knownSigs.add(sig.id);
  }

  // Latency
  const newAvgLatencyP50 = ema(baseline.avgLatencyP50, latencyStats.p50);
  const newAvgLatencyP95 = ema(baseline.avgLatencyP95, latencyStats.p95);
  const newAvgOriginTTFB = ema(baseline.avgOriginTTFB, latencyStats.originTTFB_p95);

  // CDN
  const newAvgCacheHitRatio = ema(
    baseline.avgCacheHitRatio,
    metrics.cacheHitRatio ?? baseline.avgCacheHitRatio
  );

  // Sample rate
  const newAvgSampleRate = ema(baseline.avgSampleRate, sampleRate);

  // Top countries — rolling merge with decay
  const newTopCountries: Record<string, number> = { ...baseline.topCountries };
  for (const geo of metrics.geoDistribution) {
    const prevPct = newTopCountries[geo.country] ?? 0;
    newTopCountries[geo.country] = ema(prevPct, geo.pct);
  }
  // Remove countries that have dropped below 0.1%
  for (const country of Object.keys(newTopCountries)) {
    if (newTopCountries[country] < 0.1) {
      delete newTopCountries[country];
    }
  }

  // Top JA4 — union with current (not decayed, just accumulated)
  const newTopJA4 = [...new Set([...baseline.topJA4])];

  // Per-domain baselines
  const newPerDomain = { ...baseline.perDomain };
  for (const domEntry of metrics.domainBreakdown) {
    const existing = newPerDomain[domEntry.domain];
    const domErrorRate = domEntry.count > 0 ? domEntry.errorCount / domEntry.count : 0;
    if (existing) {
      newPerDomain[domEntry.domain] = {
        avgRps: ema(existing.avgRps, domEntry.count),
        avgErrorRate: ema(existing.avgErrorRate, domErrorRate),
        avgSecEvents: ema(existing.avgSecEvents, 0), // Security events per domain not tracked in agg
      };
    } else {
      newPerDomain[domEntry.domain] = {
        avgRps: domEntry.count,
        avgErrorRate: domErrorRate,
        avgSecEvents: 0,
      };
    }
  }

  // Per-watch-path baselines
  const newPerWatchPath = { ...baseline.perWatchPath };
  for (const pathEntry of metrics.hotPaths) {
    const existing = newPerWatchPath[pathEntry.path];
    if (existing) {
      newPerWatchPath[pathEntry.path] = {
        avgRps: ema(existing.avgRps, pathEntry.count),
        avgErrorRate: ema(existing.avgErrorRate, pathEntry.errorRate),
        avgLatencyP95: existing.avgLatencyP95, // Updated from Track 3 if available
      };
    } else {
      newPerWatchPath[pathEntry.path] = {
        avgRps: pathEntry.count,
        avgErrorRate: pathEntry.errorRate,
        avgLatencyP95: 0,
      };
    }
  }

  return {
    avgRps: newAvgRps,
    stdDevRps: newStdDevRps,
    avgSampleRate: newAvgSampleRate,
    avgErrorRate: newAvgErrorRate,
    avg5xxRate: newAvg5xxRate,
    avg4xxRate: newAvg4xxRate,
    avgSecEvents: newAvgSecEvents,
    avgWafBlocks: newAvgWafBlocks,
    avgThreatMeshHits: newAvgThreatMeshHits,
    avgBotRatio: newAvgBotRatio,
    knownSignatureIds: Array.from(knownSigs),
    avgLatencyP50: newAvgLatencyP50,
    avgLatencyP95: newAvgLatencyP95,
    avgOriginTTFB: newAvgOriginTTFB,
    avgCacheHitRatio: newAvgCacheHitRatio,
    topCountries: newTopCountries,
    topJA4: newTopJA4,
    perDomain: newPerDomain,
    perWatchPath: newPerWatchPath,
    sampleCount: n,
    lastUpdated: new Date().toISOString(),
  };
}

// =============================================================================
// Threat Level Calculator
// =============================================================================

/**
 * Computes the overall threat level from active anomalies, alerts, and incidents.
 *
 * From spec Section 9.3:
 *   CRITICAL: Any CRITICAL anomaly OR origin down OR DNS down OR F5 critical alert OR Magecart
 *   HIGH:     Any HIGH anomaly OR active DDoS (L7 or L3/L4) OR F5 major alert
 *   ELEVATED: Any MEDIUM anomaly OR >= 2 concurrent anomalies OR F5 minor alert
 *   NOMINAL:  No anomalies, all metrics within baseline
 */
export function computeThreatLevel(
  anomalies: Anomaly[],
  alerts: AlertEntry[],
  incidents: Incident[]
): ThreatLevel {
  // Filter to active (unresolved) anomalies only
  const activeAnomalies = anomalies.filter((a) => !a.resolved);

  if (activeAnomalies.length === 0 && alerts.length === 0 && incidents.length === 0) {
    return 'NOMINAL';
  }

  // Check for CRITICAL conditions
  const hasCriticalAnomaly = activeAnomalies.some((a) => a.severity === 'CRITICAL');
  const hasCriticalAlert = alerts.some((a) => a.severity === 'critical');
  const hasCriticalIncident = incidents.some(
    (i) => i.status === 'active' && i.severity === 'CRITICAL'
  );

  if (hasCriticalAnomaly || hasCriticalAlert || hasCriticalIncident) {
    return 'CRITICAL';
  }

  // Check for HIGH conditions
  const hasHighAnomaly = activeAnomalies.some((a) => a.severity === 'HIGH');
  const hasMajorAlert = alerts.some((a) => a.severity === 'major');
  const hasHighIncident = incidents.some(
    (i) => i.status === 'active' && i.severity === 'HIGH'
  );

  if (hasHighAnomaly || hasMajorAlert || hasHighIncident) {
    return 'HIGH';
  }

  // Check for ELEVATED conditions
  const hasMediumAnomaly = activeAnomalies.some((a) => a.severity === 'MEDIUM');
  const hasMinorAlert = alerts.some((a) => a.severity === 'minor');
  const multipleAnomalies = activeAnomalies.length >= 2;

  if (hasMediumAnomaly || hasMinorAlert || multipleAnomalies) {
    return 'ELEVATED';
  }

  // INFO-only anomalies still count as elevated awareness
  if (activeAnomalies.length > 0) {
    return 'ELEVATED';
  }

  return 'NOMINAL';
}

// =============================================================================
// Anomaly Resolution
// =============================================================================

/**
 * Merges new anomalies with existing ones.
 * - If a new anomaly matches an existing active anomaly (same detector ID),
 *   update the lastDetectedAt timestamp instead of creating a duplicate.
 * - If an existing anomaly's detector ID is no longer firing, mark as resolved.
 *
 * @param existing - Currently tracked anomalies
 * @param newDetections - Newly detected anomalies from evaluateDetectors
 * @returns Merged anomaly list
 */
export function reconcileAnomalies(
  existing: Anomaly[],
  newDetections: Anomaly[]
): Anomaly[] {
  const now = new Date().toISOString();
  const newDetectorIds = new Set(newDetections.map((a) => a.detectorId));
  const result: Anomaly[] = [];

  // Process existing anomalies
  for (const anomaly of existing) {
    if (anomaly.resolved) {
      // Keep resolved anomalies as-is (they'll age out via ring buffer)
      result.push(anomaly);
      continue;
    }

    if (newDetectorIds.has(anomaly.detectorId)) {
      // Still firing — update timestamp, merge severity upward
      const newMatch = newDetections.find((n) => n.detectorId === anomaly.detectorId);
      if (newMatch) {
        result.push({
          ...anomaly,
          lastDetectedAt: now,
          message: newMatch.message,
          triggerValue: newMatch.triggerValue,
          severity: severityMax(anomaly.severity, newMatch.severity),
        });
        // Remove from newDetections to avoid duplicate
        newDetectorIds.delete(anomaly.detectorId);
      }
    } else {
      // No longer firing — resolve
      result.push({
        ...anomaly,
        resolved: true,
        resolvedAt: now,
      });
    }
  }

  // Add genuinely new anomalies (detector IDs not already tracked)
  for (const detection of newDetections) {
    if (newDetectorIds.has(detection.detectorId)) {
      result.push(detection);
    }
  }

  return result;
}

/**
 * Returns the higher of two severity levels.
 */
function severityMax(a: AnomalySeverity, b: AnomalySeverity): AnomalySeverity {
  const order: Record<AnomalySeverity, number> = {
    INFO: 0,
    MEDIUM: 1,
    HIGH: 2,
    CRITICAL: 3,
  };
  return order[a] >= order[b] ? a : b;
}
