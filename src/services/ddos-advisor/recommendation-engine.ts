import type {
  CurrentDdosConfig,
  TrafficStats,
  DdosFinding,
  RpsRecommendation,
  RecommendedDdosConfig,
  SeverityLevel,
  TrafficProfile,
} from './types';

const ALL_IP_THREAT_CATEGORIES = [
  'SPAM_SOURCES', 'WINDOWS_EXPLOITS', 'WEB_ATTACKS', 'BOTNETS',
  'SCANNERS', 'REPUTATION', 'PHISHING', 'PROXY', 'MOBILE_THREATS',
  'TOR_PROXY', 'DENIAL_OF_SERVICE', 'NETWORK',
];

// ═══════════════════════════════════════════════════════════════════
// RPS THRESHOLD RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════

export function generateRpsRecommendations(stats: TrafficStats): RpsRecommendation[] {
  const peakRps = stats.peakRps;
  const multiplier = 3;
  const MIN_THRESHOLD = 100;
  const calculated = Math.ceil(peakRps * multiplier);
  const threshold = Math.max(calculated, MIN_THRESHOLD);
  const wasFloored = calculated < MIN_THRESHOLD;

  const formulaStr = wasFloored
    ? `Peak=${peakRps} × ${multiplier} = ${calculated} (raised to minimum ${MIN_THRESHOLD})`
    : `Peak=${peakRps} × ${multiplier} = ${threshold}`;

  const descStr = wasFloored
    ? `Peak observed RPS was ${peakRps.toLocaleString()}. Calculated threshold (${calculated} RPS) is below the recommended minimum of ${MIN_THRESHOLD} RPS. A minimum of ${MIN_THRESHOLD} RPS is recommended to avoid false positives from normal traffic bursts.`
    : `Peak observed RPS was ${peakRps.toLocaleString()}. Setting DDoS threshold at 3× peak (${threshold.toLocaleString()} RPS) provides headroom for legitimate traffic spikes while protecting against volumetric attacks.`;

  return [{
    algorithm: 'peak_3x',
    label: wasFloored ? `Minimum Threshold` : 'Peak RPS × 3',
    rpsThreshold: threshold,
    description: descStr,
    formula: formulaStr,
    isRecommended: true,
  }];
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS FOR TRAFFIC-AWARE RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════

function getTrafficTypeLabel(profile: TrafficProfile): string {
  switch (profile.type) {
    case 'api': return `API traffic (${profile.apiTrafficPct}% programmatic)`;
    case 'web': return `Web traffic (${profile.webTrafficPct}% browser-based)`;
    case 'mixed': return `Mixed traffic (${profile.apiTrafficPct}% API, ${profile.webTrafficPct}% web)`;
  }
}

function getRecommendedMitigationAction(profile: TrafficProfile): {
  action: string;
  configKey: string;
  configValue: Record<string, unknown>;
  rationale: string;
} {
  switch (profile.type) {
    case 'api':
      return {
        action: 'Block',
        configKey: 'mitigation_block',
        configValue: {},
        rationale: 'API clients cannot execute JavaScript challenges or solve CAPTCHAs. Block is the only effective mitigation action for programmatic API traffic. Use DDoS mitigation rules (IP prefix / client source) for granular allow/deny control.',
      };
    case 'web':
      return {
        action: 'JS Challenge',
        configKey: 'mitigation_js_challenge',
        configValue: { js_script_delay: 5000, cookie_expiry: 3600 },
        rationale: 'JS Challenge is transparent to legitimate browser users while filtering automated attack tools. Real browsers execute JavaScript seamlessly; attack bots cannot.',
      };
    case 'mixed':
      return {
        action: 'JS Challenge (with custom DDoS policy for API routes)',
        configKey: 'mitigation_js_challenge',
        configValue: { js_script_delay: 5000, cookie_expiry: 3600 },
        rationale: 'Your traffic includes both browser and API clients. JS Challenge works for browser traffic but will break API clients. Configure a custom DDoS service policy with route-level rules: use JS Challenge for web paths and Block (or exempt) for API endpoints.',
      };
  }
}

function getRecommendedClientsideAction(profile: TrafficProfile): {
  action: string;
  configKey: string;
  configValue: Record<string, unknown>;
  rationale: string;
} {
  switch (profile.type) {
    case 'api':
      return {
        action: 'None',
        configKey: 'clientside_action_none',
        configValue: {},
        rationale: 'Client-side challenges (JS Challenge, CAPTCHA) cannot be served to API clients. For API-heavy traffic, client-side action must be disabled to avoid blocking legitimate programmatic requests during DDoS detection.',
      };
    case 'web':
      return {
        action: 'JS Challenge (for high-value targets)',
        configKey: 'clientside_action_js_challenge',
        configValue: { js_script_delay: 5000, cookie_expiry: 3600 },
        rationale: 'During an active DDoS attack, applying JS Challenge to ALL visitors provides an additional defense layer. Legitimate browsers pass transparently, while automated traffic is filtered. Recommended for high-value or frequently attacked sites.',
      };
    case 'mixed':
      return {
        action: 'None (API clients cannot handle challenges)',
        configKey: 'clientside_action_none',
        configValue: {},
        rationale: 'With mixed web/API traffic, enabling client-side challenges would break API clients during DDoS attacks. Keep client-side action disabled and rely on per-source mitigation (L7 DDoS detection + mitigation rules).',
      };
  }
}

// ═══════════════════════════════════════════════════════════════════
// FINDINGS (security gaps and recommendations)
// ═══════════════════════════════════════════════════════════════════

export function generateFindings(
  config: CurrentDdosConfig,
  stats: TrafficStats,
  rpsRecs: RpsRecommendation[]
): DdosFinding[] {
  const findings: DdosFinding[] = [];
  const profile = stats.trafficProfile;
  const trafficLabel = getTrafficTypeLabel(profile);
  const mitigationRec = getRecommendedMitigationAction(profile);
  const clientsideRec = getRecommendedClientsideAction(profile);

  // --- Traffic Profile Finding (informational) ---
  findings.push({
    category: 'ddos_policy',
    severity: 'info',
    title: `Traffic Profile: ${profile.type.charAt(0).toUpperCase() + profile.type.slice(1)}`,
    currentValue: trafficLabel,
    recommendedValue: 'Recommendations below are tailored to this traffic type',
    description: `Detected ${trafficLabel}. UA breakdown: ${profile.uaBreakdown.browser} browser, ${profile.uaBreakdown.mobile} mobile, ${profile.uaBreakdown.api} API client, ${profile.uaBreakdown.bot} bot, ${profile.uaBreakdown.unknown} unknown.`,
    rationale: profile.type === 'api'
      ? 'API traffic cannot execute JavaScript challenges or CAPTCHAs. Mitigation recommendations are adjusted to use block-based actions instead.'
      : profile.type === 'mixed'
        ? 'Mixed traffic requires careful DDoS configuration. JavaScript challenges work for browsers but break API clients. Consider route-level DDoS policies for optimal protection.'
        : 'Browser-based traffic supports JavaScript challenges, which provide the best balance of protection and user experience.',
  });

  // --- L7 DDoS Protection ---
  if (!config.hasL7DdosProtection) {
    findings.push({
      category: 'rps_threshold',
      severity: 'critical',
      title: 'L7 DDoS Protection Not Configured',
      currentValue: 'Not configured',
      recommendedValue: `Enable with tuned RPS threshold + ${mitigationRec.action}`,
      description: 'L7 DDoS auto-mitigation is not enabled. The LB has no automatic protection against application-layer DDoS attacks.',
      rationale: `Without L7 DDoS protection, volumetric application-layer attacks can overwhelm origin servers. Enable protection with a tuned RPS threshold and ${mitigationRec.action} mitigation action (${profile.type} traffic detected).`,
    });
  } else {
    // RPS Threshold analysis
    const recommended = rpsRecs.find(r => r.isRecommended);
    const currentThreshold = config.rpsThreshold || 10000;

    if (config.isDefaultRpsThreshold) {
      const severity: SeverityLevel = stats.aggregateRps.max < 1000 ? 'high' : 'medium';
      findings.push({
        category: 'rps_threshold',
        severity,
        title: 'Using Default RPS Threshold (10,000)',
        currentValue: '10,000 RPS (system default)',
        recommendedValue: recommended ? `${recommended.rpsThreshold} RPS (${recommended.label})` : 'Tune based on traffic',
        description: `The default 10,000 RPS threshold is not tuned for this LB. Your peak observed RPS is ${stats.aggregateRps.max}.`,
        rationale: stats.aggregateRps.max < 1000
          ? `Your peak traffic is only ${stats.aggregateRps.max} RPS — the default 10,000 threshold is ${Math.round(10000 / Math.max(stats.aggregateRps.max, 1))}x higher than your peak. This means an attacker can send up to ${10000 - stats.aggregateRps.max} extra RPS before mitigation triggers. Lower the threshold for tighter protection.`
          : `Your peak traffic is ${stats.aggregateRps.max} RPS. Consider tuning the threshold to match your actual traffic patterns for optimal protection.`,
      });
    } else if (recommended && currentThreshold > recommended.rpsThreshold * 3) {
      findings.push({
        category: 'rps_threshold',
        severity: 'medium',
        title: 'RPS Threshold Significantly Over-Provisioned',
        currentValue: `${currentThreshold} RPS`,
        recommendedValue: `${recommended.rpsThreshold} RPS (${recommended.label})`,
        description: `Current threshold is ${Math.round(currentThreshold / Math.max(stats.aggregateRps.max, 1))}x your peak traffic. Consider lowering for tighter protection.`,
        rationale: `A threshold far above actual traffic means an attacker has a large window before mitigation triggers. Tighter thresholds provide faster response to volumetric attacks.`,
      });
    } else if (recommended && currentThreshold < stats.aggregateRps.p99) {
      findings.push({
        category: 'rps_threshold',
        severity: 'high',
        title: 'RPS Threshold Too Low — May Cause False Positives',
        currentValue: `${currentThreshold} RPS`,
        recommendedValue: `${recommended.rpsThreshold} RPS (${recommended.label})`,
        description: `Current threshold (${currentThreshold}) is below your P99 traffic (${stats.aggregateRps.p99} RPS). Legitimate traffic spikes may trigger DDoS mitigation.`,
        rationale: 'When the threshold is below normal peak traffic, legitimate requests during busy periods may be incorrectly mitigated. Raise the threshold above P99 with a safety margin.',
      });
    } else {
      findings.push({
        category: 'rps_threshold',
        severity: 'info',
        title: 'RPS Threshold Configured',
        currentValue: `${currentThreshold} RPS`,
        recommendedValue: recommended ? `${recommended.rpsThreshold} RPS (${recommended.label})` : 'Current value appears reasonable',
        description: `Custom RPS threshold is set. Peak observed: ${stats.aggregateRps.max} RPS, P99: ${stats.aggregateRps.p99} RPS.`,
        rationale: 'The current threshold appears to be within a reasonable range based on observed traffic.',
      });
    }
  }

  // --- Mitigation Action (traffic-type aware) ---
  if (config.mitigationAction === 'not_configured') {
    findings.push({
      category: 'mitigation_action',
      severity: config.hasL7DdosProtection ? 'high' : 'medium',
      title: 'No DDoS Mitigation Action Configured',
      currentValue: 'Not configured',
      recommendedValue: mitigationRec.action,
      description: `No automatic mitigation action is set for suspicious sources during a DDoS attack. Traffic type: ${trafficLabel}.`,
      rationale: mitigationRec.rationale,
    });
  } else if (config.mitigationAction === 'none') {
    findings.push({
      category: 'mitigation_action',
      severity: 'high',
      title: 'DDoS Mitigation Explicitly Disabled',
      currentValue: 'None (disabled)',
      recommendedValue: mitigationRec.action,
      description: `Mitigation is explicitly disabled. Suspicious sources will NOT be mitigated during attacks. Traffic type: ${trafficLabel}.`,
      rationale: `Even with detection enabled, disabling mitigation means attacks are detected but not acted upon. ${mitigationRec.rationale}`,
    });
  } else if (config.mitigationAction === 'js_challenge' && profile.type === 'api') {
    findings.push({
      category: 'mitigation_action',
      severity: 'critical',
      title: 'JS Challenge Cannot Work for API Traffic',
      currentValue: 'JS Challenge',
      recommendedValue: 'Block',
      description: `JS Challenge is configured, but ${profile.apiTrafficPct}% of your traffic is from API clients (${profile.uaBreakdown.api} programmatic, ${profile.uaBreakdown.bot} bot requests). API clients cannot execute JavaScript.`,
      rationale: 'JavaScript Challenge requires a browser engine to execute the challenge script. API clients (curl, SDKs, mobile apps, microservices) will fail the challenge and be blocked. Switch to Block for API traffic, or use a custom DDoS policy with route-level rules if you have both API and web paths.',
    });
  } else if (config.mitigationAction === 'js_challenge' && profile.type === 'mixed') {
    findings.push({
      category: 'mitigation_action',
      severity: 'high',
      title: 'JS Challenge May Break API Clients',
      currentValue: 'JS Challenge',
      recommendedValue: 'Custom DDoS policy with route-level rules',
      description: `JS Challenge is configured, but ${profile.apiTrafficPct}% of traffic is from programmatic API clients that cannot execute JavaScript.`,
      rationale: 'Create a custom DDoS service policy with route-level rules: apply JS Challenge to web/browser paths and Block (or exempt) API endpoints. This protects web traffic without breaking API clients.',
    });
  } else if (config.mitigationAction === 'captcha_challenge' && (profile.type === 'api' || profile.type === 'mixed')) {
    findings.push({
      category: 'mitigation_action',
      severity: profile.type === 'api' ? 'critical' : 'high',
      title: 'CAPTCHA Challenge Incompatible with API Traffic',
      currentValue: 'CAPTCHA Challenge',
      recommendedValue: profile.type === 'api' ? 'Block' : 'Custom DDoS policy with route-level rules',
      description: `CAPTCHA challenges require human interaction. ${profile.apiTrafficPct}% of your traffic is programmatic and will fail CAPTCHA verification.`,
      rationale: profile.type === 'api'
        ? 'API clients cannot solve CAPTCHAs. Switch to Block for pure API traffic.'
        : 'For mixed traffic, use a custom DDoS policy with per-route rules: CAPTCHA for web paths, Block for API paths.',
    });
  } else if (config.mitigationAction === 'block') {
    if (profile.type === 'web') {
      findings.push({
        category: 'mitigation_action',
        severity: 'low',
        title: 'Mitigation Action: Block (Consider JS Challenge for Web Traffic)',
        currentValue: 'Block',
        recommendedValue: 'JS Challenge',
        description: 'Your traffic is primarily browser-based. JS Challenge provides equally effective protection with fewer false positives for shared IP scenarios.',
        rationale: 'JS Challenge transparently verifies legitimate browsers without blocking them. Block is more aggressive and may cause collateral damage when multiple users share IP addresses (corporate proxies, mobile carriers). Since your traffic is web-based, JS Challenge is the optimal choice.',
      });
    } else {
      findings.push({
        category: 'mitigation_action',
        severity: 'info',
        title: 'Mitigation Action: Block (Appropriate for API Traffic)',
        currentValue: 'Block',
        recommendedValue: 'Block (correct for API traffic)',
        description: `Block is the correct mitigation action for ${trafficLabel}. API clients cannot handle JS Challenge or CAPTCHA.`,
        rationale: 'For API and programmatic traffic, Block is the only effective mitigation action. Use DDoS mitigation rules (IP prefix lists, client source rules) to create allow-lists for known API consumers.',
      });
    }
  }

  // --- Client-side Action (traffic-type aware) ---
  if (config.hasL7DdosProtection) {
    if (config.clientsideAction === 'not_configured') {
      findings.push({
        category: 'clientside_action',
        severity: profile.type === 'web' ? 'low' : 'info',
        title: 'No Client-side Action During Attack',
        currentValue: 'Not configured',
        recommendedValue: clientsideRec.action,
        description: `No challenge is applied to ALL traffic during a DDoS attack. Only suspicious sources are mitigated. Traffic type: ${trafficLabel}.`,
        rationale: clientsideRec.rationale,
      });
    } else if (config.clientsideAction === 'js_challenge' && (profile.type === 'api' || profile.type === 'mixed')) {
      findings.push({
        category: 'clientside_action',
        severity: profile.type === 'api' ? 'critical' : 'high',
        title: 'Client-side JS Challenge Will Break API Clients During Attack',
        currentValue: 'JS Challenge (applied to ALL traffic during attack)',
        recommendedValue: 'None',
        description: `During a DDoS attack, JS Challenge is applied to ALL visitors including ${profile.apiTrafficPct}% API clients that cannot execute JavaScript. This effectively blocks all API traffic during any DDoS event.`,
        rationale: `Client-side action applies to EVERY request, not just suspicious ones. With ${profile.type} traffic, this means legitimate API consumers are challenged and will fail. Set to None and rely on per-source mitigation instead.`,
      });
    } else if (config.clientsideAction === 'captcha_challenge' && (profile.type === 'api' || profile.type === 'mixed')) {
      findings.push({
        category: 'clientside_action',
        severity: profile.type === 'api' ? 'critical' : 'high',
        title: 'Client-side CAPTCHA Will Block All API Traffic During Attack',
        currentValue: 'CAPTCHA Challenge (applied to ALL traffic during attack)',
        recommendedValue: 'None',
        description: `During a DDoS attack, all visitors must solve CAPTCHA including ${profile.apiTrafficPct}% API clients. Programmatic clients cannot solve CAPTCHAs.`,
        rationale: 'Disable client-side CAPTCHA when API clients are present. Use per-source mitigation with Block action for API traffic instead.',
      });
    }
  }

  // --- DDoS Mitigation Rules (source-based recommendations) ---
  if (config.mitigationRules.length === 0 && stats.topCountries.length > 0) {
    // Check if traffic is concentrated from specific geos that may indicate bot/attack patterns
    const totalReqs = stats.totalRequests;
    const suspiciousGeos = stats.topCountries.filter(c => {
      const pct = (c.count / totalReqs) * 100;
      return pct > 20; // Countries with >20% of traffic
    });

    if (suspiciousGeos.length > 0 && profile.type !== 'api') {
      findings.push({
        category: 'mitigation_rules',
        severity: 'low',
        title: 'Consider Geo-Based DDoS Mitigation Rules',
        currentValue: 'No DDoS mitigation rules configured',
        recommendedValue: 'Add rules for known-bad or unexpected source regions',
        description: `Top traffic sources: ${suspiciousGeos.map(c => `${c.country} (${((c.count / totalReqs) * 100).toFixed(1)}%)`).join(', ')}. DDoS mitigation rules can apply stronger mitigation to specific IP ranges, countries, or ASNs.`,
        rationale: 'DDoS mitigation rules allow targeted policies for specific source networks. You can block or challenge traffic from unexpected geographic regions, known-bad ASNs, or specific IP ranges. This provides defense-in-depth alongside the RPS threshold.',
      });
    }
  } else if (config.mitigationRules.length > 0) {
    findings.push({
      category: 'mitigation_rules',
      severity: 'info',
      title: `${config.mitigationRules.length} DDoS Mitigation Rule(s) Configured`,
      currentValue: config.mitigationRules.map(r => `${r.name} (${r.type}: ${r.detail})`).join('; '),
      recommendedValue: 'Review periodically based on attack patterns',
      description: `Active rules: ${config.mitigationRules.map(r => r.name).join(', ')}. These rules apply specific mitigation actions to matching traffic sources.`,
      rationale: 'DDoS mitigation rules provide targeted source-based protection. Review these rules periodically and update based on evolving attack patterns and traffic changes.',
    });
  }

  // --- Custom DDoS Policy ---
  if (profile.type === 'mixed' && !config.ddosPolicy) {
    findings.push({
      category: 'ddos_policy',
      severity: 'high',
      title: 'Mixed Traffic Needs Custom DDoS Policy',
      currentValue: 'No custom DDoS policy',
      recommendedValue: 'Create custom service policy with route-level rules',
      description: `Your LB serves both web (${profile.webTrafficPct}%) and API (${profile.apiTrafficPct}%) traffic. A single mitigation action cannot optimally protect both traffic types.`,
      rationale: 'Create a custom DDoS service policy with route-specific rules: apply JS Challenge to web/browser paths (e.g., /*, /app/*) and Block or exempt API paths (e.g., /api/*, /v1/*). This ensures browser users get transparent challenges while API clients are handled appropriately.',
    });
  } else if (config.ddosPolicy) {
    findings.push({
      category: 'ddos_policy',
      severity: 'info',
      title: `Custom DDoS Policy: ${config.ddosPolicy}`,
      currentValue: config.ddosPolicy,
      recommendedValue: 'Review policy rules match current traffic patterns',
      description: 'A custom DDoS service policy is configured for route-level or source-level mitigation control.',
      rationale: 'Custom DDoS policies provide granular control over mitigation actions per route, source, or request attributes. Ensure the policy rules are current with your traffic patterns.',
    });
  }

  // --- Slow DDoS Mitigation ---
  if (!config.hasSlowDdosMitigation) {
    const recHeadersTimeout = Math.max(Math.ceil(stats.p95DurationMs / 1000) * 2, 10);
    const recRequestTimeout = Math.max(Math.ceil(stats.p99DurationMs / 1000) * 3, 30);
    findings.push({
      category: 'slow_ddos',
      severity: 'medium',
      title: 'Slow DDoS Mitigation Not Configured',
      currentValue: 'System defaults',
      recommendedValue: `Headers timeout: ${recHeadersTimeout}s, Request timeout: ${recRequestTimeout}s`,
      description: `No custom timeouts for slow DDoS attacks (Slowloris, Slow POST). System defaults may be too permissive. Traffic type: ${trafficLabel}.`,
      rationale: profile.type === 'api'
        ? `API traffic typically completes faster than web requests. Your P95 response time is ${stats.p95DurationMs}ms, P99 is ${stats.p99DurationMs}ms. Set tight timeouts (headers: ${recHeadersTimeout}s, request: ${recRequestTimeout}s) to quickly identify and terminate slow-rate attacks while accommodating your actual API response times.`
        : `Based on your traffic, P95 response time is ${stats.p95DurationMs}ms and P99 is ${stats.p99DurationMs}ms. Custom timeouts based on these values protect against Slowloris and Slow POST attacks while accommodating legitimate slow connections. Headers timeout controls how long the server waits for complete request headers; request timeout controls total request duration.`,
    });
  } else {
    // Validate existing slow DDoS timeouts against actual traffic
    const headersMs = config.slowDdosHeadersTimeout || 0;
    const requestMs = config.slowDdosRequestTimeout || 0;
    if (headersMs > 0 && headersMs < stats.p95DurationMs) {
      findings.push({
        category: 'slow_ddos',
        severity: 'medium',
        title: 'Slow DDoS Headers Timeout May Be Too Aggressive',
        currentValue: `${headersMs}ms (${(headersMs / 1000).toFixed(1)}s)`,
        recommendedValue: `${Math.max(Math.ceil(stats.p95DurationMs / 1000) * 2, 10)}s`,
        description: `Headers timeout (${headersMs}ms) is below your P95 response time (${stats.p95DurationMs}ms). Legitimate slow connections may be terminated.`,
        rationale: 'Set headers timeout to at least 2x your P95 response time to avoid terminating legitimate slow connections.',
      });
    }
    if (requestMs > 0 && requestMs > 300000) {
      findings.push({
        category: 'slow_ddos',
        severity: 'low',
        title: 'Slow DDoS Request Timeout Very Permissive',
        currentValue: `${requestMs}ms (${(requestMs / 1000).toFixed(0)}s)`,
        recommendedValue: `${Math.max(Math.ceil(stats.p99DurationMs / 1000) * 3, 30)}s`,
        description: `Request timeout (${(requestMs / 1000).toFixed(0)}s) is very high. Slow POST attacks could tie up connections for extended periods.`,
        rationale: 'Tighter request timeouts limit the impact of slow POST attacks. Set to 3x your P99 response time for a reasonable balance.',
      });
    }
    if (headersMs > 0 && requestMs > 0) {
      findings.push({
        category: 'slow_ddos',
        severity: 'info',
        title: 'Slow DDoS Mitigation Configured',
        currentValue: `Headers: ${(headersMs / 1000).toFixed(1)}s, Request: ${(requestMs / 1000).toFixed(0)}s`,
        recommendedValue: 'Current values appear reasonable',
        description: `Custom slow DDoS timeouts are configured. Your P95 response: ${stats.p95DurationMs}ms, P99: ${stats.p99DurationMs}ms.`,
        rationale: 'Slow DDoS mitigation provides protection against Slowloris and Slow POST attacks by enforcing request and header completion timeouts.',
      });
    }
  }

  // --- Threat Mesh ---
  if (!config.threatMeshEnabled) {
    findings.push({
      category: 'threat_mesh',
      severity: 'high',
      title: 'Threat Mesh Disabled',
      currentValue: 'Disabled',
      recommendedValue: 'Enable',
      description: 'F5 XC Threat Mesh cross-references traffic against global threat intelligence from all F5 XC customers.',
      rationale: 'Threat Mesh leverages collective intelligence across the entire F5 XC network to identify malicious sources. IPs flagged as attackers on other F5 XC sites are automatically flagged on yours. There is no performance cost and it works regardless of traffic type (API or web).',
    });
  }

  // --- IP Reputation ---
  if (!config.ipReputationEnabled) {
    findings.push({
      category: 'ip_reputation',
      severity: 'high',
      title: 'IP Reputation Not Enabled',
      currentValue: 'Disabled',
      recommendedValue: 'Enable with all 12 threat categories',
      description: 'IP Reputation scoring is not enabled. Known malicious IPs (botnets, scanners, proxies, tor) are not being flagged.',
      rationale: 'IP Reputation adds zero-latency threat intelligence by checking source IPs against continuously updated threat feeds. Enable all 12 threat categories for comprehensive coverage. This works for both API and web traffic with no client-side requirements.',
    });
  } else {
    const missing = ALL_IP_THREAT_CATEGORIES.filter(c => !config.ipThreatCategories.includes(c));
    if (missing.length > 0) {
      findings.push({
        category: 'ip_reputation',
        severity: 'medium',
        title: `IP Reputation Missing ${missing.length} Threat Categories`,
        currentValue: `${config.ipThreatCategories.length}/${ALL_IP_THREAT_CATEGORIES.length} categories`,
        recommendedValue: 'Enable all 12 categories',
        description: `Missing categories: ${missing.join(', ')}`,
        rationale: 'Each threat category covers a different attack vector. Missing categories create blind spots in IP reputation scoring. Particularly important: DENIAL_OF_SERVICE, BOTNETS, and SCANNERS for DDoS protection.',
      });
    } else {
      findings.push({
        category: 'ip_reputation',
        severity: 'info',
        title: 'IP Reputation Fully Configured',
        currentValue: `All ${ALL_IP_THREAT_CATEGORIES.length} categories enabled`,
        recommendedValue: 'No change needed',
        description: 'All IP threat categories are enabled for comprehensive coverage.',
        rationale: 'Full IP reputation coverage provides the widest threat intelligence visibility.',
      });
    }
  }

  // --- Malicious User Detection ---
  if (!config.maliciousUserDetectionEnabled) {
    findings.push({
      category: 'malicious_user_detection',
      severity: 'high',
      title: 'Malicious User Detection Disabled',
      currentValue: 'Disabled',
      recommendedValue: 'Enable',
      description: 'F5 XC Malicious User Detection uses ML to identify and adaptively mitigate suspicious users based on behavior patterns.',
      rationale: profile.type === 'api'
        ? 'Malicious User Detection tracks per-user behavior (WAF violations, bot signals, IP reputation) and applies progressive mitigation. For API traffic, it uses blocking rather than challenges. Requires User Identification policy to be configured.'
        : 'Malicious User Detection tracks per-user behavior (WAF violations, bot signals, IP reputation) and automatically applies progressive challenges (alert → JS Challenge → CAPTCHA → temporary block). It provides adaptive, user-level protection without manual rules.',
    });
  }

  // --- Bot Defense ---
  if (!config.botDefenseEnabled) {
    findings.push({
      category: 'bot_defense',
      severity: profile.type === 'web' ? 'medium' : 'low',
      title: 'Bot Defense Not Enabled',
      currentValue: 'Disabled',
      recommendedValue: profile.type === 'api' ? 'Consider for web-facing endpoints' : 'Enable',
      description: 'Bot Defense uses JavaScript-based detection to classify and mitigate automated traffic.',
      rationale: profile.type === 'api'
        ? 'Bot Defense relies on JavaScript injection which does not work for API clients. If you have any web-facing paths, enable Bot Defense selectively for those routes. For pure API traffic, rely on IP Reputation, Malicious User Detection, and rate limiting instead.'
        : profile.type === 'mixed'
          ? 'Bot Defense is effective for web/browser traffic but will not work for API paths. Configure it for your web-facing routes. Many DDoS attacks use botnets — Bot Defense identifies and classifies automated traffic for better mitigation decisions.'
          : 'Many DDoS attacks use botnets and automated tools. Bot Defense identifies and classifies automated traffic, enabling more accurate mitigation decisions. It injects lightweight JavaScript that is transparent to legitimate browsers.',
    });
  }

  // --- Security Events Analysis ---
  if (stats.ddosEventCount > 0) {
    findings.push({
      category: 'ddos_policy',
      severity: 'medium',
      title: `${stats.ddosEventCount} DDoS Events Detected in Analysis Period`,
      currentValue: `${stats.ddosEventCount} DDoS events, ${stats.wafEventCount} WAF events, ${stats.botEventCount} bot events`,
      recommendedValue: 'Review and tune settings based on event patterns',
      description: `Security events during the analysis period indicate active attacks or suspicious activity. ${stats.ddosEventCount} DDoS-related events were recorded.`,
      rationale: 'Active DDoS events during the analysis period confirm that your load balancer is being targeted. This strengthens the case for tighter DDoS protection settings. Review the specific events to identify attack patterns and sources.',
    });
  }

  // --- User Reputation Analysis ---
  const { flagged, malicious } = stats.userReputationSummary;
  if (flagged + malicious > 0) {
    const total = stats.userReputationSummary.clean + stats.userReputationSummary.benignBot + flagged + malicious;
    const badPct = ((flagged + malicious) / Math.max(total, 1) * 100).toFixed(1);
    findings.push({
      category: 'malicious_user_detection',
      severity: malicious > 0 ? 'medium' : 'low',
      title: `${flagged + malicious} Suspicious Users Detected (${badPct}%)`,
      currentValue: `${malicious} malicious, ${flagged} flagged out of ${total} unique users`,
      recommendedValue: config.maliciousUserDetectionEnabled ? 'Monitor and tune policies' : 'Enable Malicious User Detection',
      description: `User reputation analysis found ${malicious} malicious and ${flagged} flagged users among ${total} unique visitors during the analysis period.`,
      rationale: 'Suspicious users may be involved in DDoS attacks, credential stuffing, or API abuse. Malicious User Detection with progressive challenges can automatically handle these users without manual intervention.',
    });
  }

  // Sort by severity
  const severityOrder: Record<SeverityLevel, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return findings;
}

// ═══════════════════════════════════════════════════════════════════
// RECOMMENDED CONFIG GENERATOR
// ═══════════════════════════════════════════════════════════════════

export function generateRecommendedConfig(
  stats: TrafficStats,
  rpsRecs: RpsRecommendation[],
  currentConfig: CurrentDdosConfig
): RecommendedDdosConfig {
  const recommended = rpsRecs.find(r => r.isRecommended) || rpsRecs[0];
  const profile = stats.trafficProfile;
  const mitigationRec = getRecommendedMitigationAction(profile);
  const clientsideRec = getRecommendedClientsideAction(profile);

  const l7: Record<string, unknown> = {
    rps_threshold: recommended.rpsThreshold,
    [mitigationRec.configKey]: mitigationRec.configValue,
    [clientsideRec.configKey]: clientsideRec.configValue,
  };

  // Add custom policy recommendation for mixed traffic
  if (profile.type === 'mixed') {
    l7['_comment'] = 'Mixed traffic detected — create a custom DDoS service policy with route-level rules for optimal protection';
    l7.ddos_policy_none = {};
  } else {
    l7.ddos_policy_none = {};
  }

  const config: RecommendedDdosConfig = {
    l7_ddos_protection: l7,
  };

  // Slow DDoS — always recommend with traffic-aware timeouts
  if (!currentConfig.hasSlowDdosMitigation) {
    // API traffic: tighter timeouts (faster expected responses)
    const headersMult = profile.type === 'api' ? 1.5 : 2;
    const requestMult = profile.type === 'api' ? 2 : 3;
    const headersTimeout = Math.max(Math.ceil(stats.p95DurationMs / 1000 * headersMult), profile.type === 'api' ? 5 : 10) * 1000;
    const requestTimeout = Math.max(Math.ceil(stats.p99DurationMs / 1000 * requestMult), profile.type === 'api' ? 15 : 30) * 1000;
    config.slow_ddos_mitigation = {
      request_headers_timeout: headersTimeout,
      request_timeout: requestTimeout,
    };
  }

  // Threat Mesh
  if (!currentConfig.threatMeshEnabled) {
    config.enable_threat_mesh = {};
  }

  // IP Reputation
  if (!currentConfig.ipReputationEnabled || currentConfig.ipThreatCategories.length < ALL_IP_THREAT_CATEGORIES.length) {
    config.enable_ip_reputation = {
      ip_threat_categories: ALL_IP_THREAT_CATEGORIES,
    };
  }

  // Malicious User Detection
  if (!currentConfig.maliciousUserDetectionEnabled) {
    config.enable_malicious_user_detection = {};
  }

  return config;
}
