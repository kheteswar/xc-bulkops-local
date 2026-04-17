import type { FieldDefinition, LogSource } from './types';

// ═══════════════════════════════════════════════════════════════════════════════
// Field definitions mapped from REAL F5 XC API responses:
//   Access logs:  fluentd.svcfw.apiaccess
//   Security logs: fluentd.svcfw.secevent
//
// source: 'access'   = only in access logs
// source: 'security'  = only in security event logs
// source: 'both'      = present in both log types
// ═══════════════════════════════════════════════════════════════════════════════

export const FIELD_DEFINITIONS: FieldDefinition[] = [
  // ── TIMING (access only) ────────────────────────────────────────────────────
  { key: 'total_duration_seconds', label: 'Total Duration (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_first_upstream_tx_byte', label: 'Client → XC TX Start (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_last_upstream_tx_byte', label: 'Client → XC TX End (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_first_upstream_rx_byte', label: 'Origin TTFB (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_last_upstream_rx_byte', label: 'Origin Full Response (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_first_downstream_tx_byte', label: 'XC → Client TX Start (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_last_downstream_tx_byte', label: 'XC → Client TX End (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'time_to_last_rx_byte', label: 'Time to Last RX Byte (s)', type: 'numeric', group: 'timing', source: 'access' },
  { key: 'rtt_upstream_seconds', label: 'RTT Upstream (s)', type: 'numeric', group: 'timing', parseAsNumber: true, source: 'access' },
  { key: 'rtt_downstream_seconds', label: 'RTT Downstream (s)', type: 'numeric', group: 'timing', parseAsNumber: true, source: 'access' },
  { key: 'duration_with_data_tx_delay', label: 'Duration w/ Data TX Delay', type: 'numeric', group: 'timing', parseAsNumber: true, source: 'access' },
  { key: 'duration_with_no_data_tx_delay', label: 'Duration w/o Data TX Delay', type: 'numeric', group: 'timing', parseAsNumber: true, source: 'access' },

  // ── REQUEST (both) ──────────────────────────────────────────────────────────
  { key: 'method', label: 'HTTP Method', type: 'string', group: 'request', source: 'both' },
  { key: 'req_path', label: 'Request Path', type: 'string', group: 'request', source: 'both' },
  { key: 'original_path', label: 'Original Path', type: 'string', group: 'request', source: 'both' },
  { key: 'authority', label: 'Authority (Host)', type: 'string', group: 'request', source: 'both' },
  { key: 'domain', label: 'Domain', type: 'string', group: 'request', source: 'both' },
  { key: 'original_authority', label: 'Original Authority', type: 'string', group: 'request', source: 'access' },
  { key: 'scheme', label: 'Scheme', type: 'string', group: 'request', source: 'access' },
  { key: 'protocol', label: 'Protocol', type: 'string', group: 'request', source: 'access' },
  { key: 'http_version', label: 'HTTP Version', type: 'string', group: 'request', source: 'both' },
  { key: 'user_agent', label: 'User Agent', type: 'string', group: 'request', source: 'both' },
  { key: 'browser_type', label: 'Browser Type', type: 'string', group: 'request', source: 'both' },
  { key: 'device_type', label: 'Device Type', type: 'string', group: 'request', source: 'both' },
  { key: 'app_type', label: 'App Type (LB)', type: 'string', group: 'request', source: 'both' },
  { key: 'referer', label: 'Referer', type: 'string', group: 'request', source: 'access' },
  { key: 'accept', label: 'Accept Header', type: 'string', group: 'request', source: 'access' },
  { key: 'req_size', label: 'Request Size (bytes)', type: 'numeric', group: 'request', parseAsNumber: true, source: 'both' },
  { key: 'req_headers_size', label: 'Request Headers Size', type: 'numeric', group: 'request', parseAsNumber: true, source: 'security' },

  // ── RESPONSE ────────────────────────────────────────────────────────────────
  { key: 'rsp_code', label: 'Response Code', type: 'string', group: 'response', source: 'both' },
  { key: 'rsp_code_class', label: 'Response Code Class', type: 'string', group: 'response', source: 'both' },
  { key: 'rsp_code_details', label: 'Response Code Details', type: 'string', group: 'response', source: 'access' },
  { key: 'rsp_size', label: 'Response Size (bytes)', type: 'numeric', group: 'response', parseAsNumber: true, source: 'both' },
  { key: 'response_flags', label: 'Response Flags', type: 'string', group: 'response', source: 'access' },

  // ── ROUTING ─────────────────────────────────────────────────────────────────
  { key: 'vh_name', label: 'Virtual Host (LB)', type: 'string', group: 'routing', source: 'both' },
  { key: 'vh_type', label: 'VH Type', type: 'string', group: 'routing', source: 'access' },
  { key: 'site', label: 'Site', type: 'string', group: 'routing', source: 'both' },
  { key: 'src_site', label: 'Source Site', type: 'string', group: 'routing', source: 'both' },
  { key: 'src_instance', label: 'Source Instance', type: 'string', group: 'routing', source: 'both' },
  { key: 'src', label: 'Source Network', type: 'string', group: 'routing', source: 'both' },
  { key: 'dst', label: 'Destination', type: 'string', group: 'routing', source: 'access' },
  { key: 'dst_ip', label: 'Destination IP (Origin)', type: 'string', group: 'routing', source: 'both' },
  { key: 'dst_port', label: 'Destination Port', type: 'string', group: 'routing', source: 'both' },
  { key: 'dst_site', label: 'Destination Site', type: 'string', group: 'routing', source: 'access' },
  { key: 'dst_instance', label: 'Destination Instance', type: 'string', group: 'routing', source: 'access' },
  { key: 'cluster_name', label: 'Cluster Name', type: 'string', group: 'routing', source: 'both' },
  { key: 'hostname', label: 'Hostname (Node)', type: 'string', group: 'routing', source: 'both' },
  { key: 'proxy_type', label: 'Proxy Type', type: 'string', group: 'routing', source: 'access' },
  { key: 'route_uuid', label: 'Route UUID', type: 'string', group: 'routing', source: 'security' },
  { key: 'node_id', label: 'Node ID', type: 'string', group: 'routing', source: 'access' },

  // ── IDENTITY / SOURCE ───────────────────────────────────────────────────────
  { key: 'src_ip', label: 'Source IP', type: 'string', group: 'security', source: 'both' },
  { key: 'x_forwarded_for', label: 'X-Forwarded-For', type: 'string', group: 'security', source: 'both' },
  { key: 'user', label: 'User Identifier', type: 'string', group: 'security', source: 'both' },
  { key: 'api_endpoint', label: 'API Endpoint', type: 'string', group: 'security', source: 'both' },

  // ── SECURITY (access log fields) ────────────────────────────────────────────
  { key: 'waf_action', label: 'WAF Action', type: 'string', group: 'security', source: 'access' },
  { key: 'bot_class', label: 'Bot Class', type: 'string', group: 'security', source: 'access' },
  { key: 'has_sec_event', label: 'Has Security Event', type: 'boolean', group: 'security', source: 'access' },

  // ── SECURITY EVENT — Classification & Action ────────────────────────────────
  { key: 'sec_event_type', label: 'Security Event Type', type: 'string', group: 'security_event', source: 'security' },
  { key: 'sec_event_name', label: 'Security Event Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'action', label: 'Action', type: 'string', group: 'security_event', source: 'security' },
  { key: 'recommended_action', label: 'Recommended Action', type: 'string', group: 'security_event', source: 'security' },
  { key: 'enforcement_mode', label: 'Enforcement Mode', type: 'string', group: 'security_event', source: 'security' },
  { key: 'waf_mode', label: 'WAF Mode', type: 'string', group: 'security_event', source: 'security' },
  { key: 'app_firewall_name', label: 'App Firewall Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'violation_rating', label: 'Violation Rating', type: 'string', group: 'security_event', source: 'security' },
  { key: 'req_risk', label: 'Request Risk', type: 'string', group: 'security_event', source: 'security' },
  { key: 'req_risk_reasons', label: 'Request Risk Reasons', type: 'string', group: 'security_event', source: 'security' },

  // ── SECURITY EVENT — Bot Info ────────────────────────────────────────────────
  { key: 'bot_info.name', label: 'Bot Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'bot_info.classification', label: 'Bot Classification', type: 'string', group: 'security_event', source: 'security' },
  { key: 'bot_info.type', label: 'Bot Type', type: 'string', group: 'security_event', source: 'security' },
  { key: 'bot_info.anomaly', label: 'Bot Anomaly', type: 'string', group: 'security_event', source: 'security' },

  // ── SECURITY EVENT — Signatures & Violations ────────────────────────────────
  { key: 'signatures.id', label: 'Signature ID', type: 'string', group: 'security_event', source: 'security' },
  { key: 'signatures.name', label: 'Signature Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'signatures.attack_type', label: 'Signature Attack Type', type: 'string', group: 'security_event', source: 'security' },
  { key: 'signatures.accuracy', label: 'Signature Accuracy', type: 'string', group: 'security_event', source: 'security' },
  { key: 'signatures.risk', label: 'Signature Risk', type: 'string', group: 'security_event', source: 'security' },
  { key: 'violations.name', label: 'Violation Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'violations.context', label: 'Violation Context', type: 'string', group: 'security_event', source: 'security' },

  // ── SECURITY EVENT — Threat Intel ───────────────────────────────────────────
  { key: 'threat_campaigns.name', label: 'Threat Campaign Name', type: 'string', group: 'security_event', source: 'security' },
  { key: 'threat_campaigns.id', label: 'Threat Campaign ID', type: 'string', group: 'security_event', source: 'security' },
  { key: 'attack_types', label: 'Attack Types', type: 'string', group: 'security_event', source: 'security' },

  // ── POLICY HITS (access logs — nested object) ───────────────────────────────
  { key: 'policy_hits.policy_hits.result', label: 'Policy Result', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.policy', label: 'Policy Name', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.policy_rule', label: 'Policy Rule', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.policy_namespace', label: 'Policy Namespace', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.ip_trustscore', label: 'IP Trust Score', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.ip_trustworthiness', label: 'IP Trustworthiness', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.ip_risk', label: 'IP Risk', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.rate_limiter_action', label: 'Rate Limiter Action', type: 'string', group: 'security', source: 'access' },
  { key: 'policy_hits.policy_hits.malicious_user_mitigate_action', label: 'Malicious User Action', type: 'string', group: 'security', source: 'access' },

  // ── GEO (both) ──────────────────────────────────────────────────────────────
  { key: 'country', label: 'Country', type: 'string', group: 'geo', source: 'both' },
  { key: 'region', label: 'Region', type: 'string', group: 'geo', source: 'both' },
  { key: 'city', label: 'City', type: 'string', group: 'geo', source: 'both' },
  { key: 'asn', label: 'ASN (name + number)', type: 'string', group: 'geo', source: 'both' },
  { key: 'as_org', label: 'AS Organization', type: 'string', group: 'geo', source: 'both' },
  { key: 'as_number', label: 'AS Number', type: 'string', group: 'geo', source: 'both' },
  { key: 'network', label: 'Network', type: 'string', group: 'geo', source: 'both' },
  { key: 'latitude', label: 'Latitude', type: 'numeric', group: 'geo', parseAsNumber: true, source: 'both' },
  { key: 'longitude', label: 'Longitude', type: 'numeric', group: 'geo', parseAsNumber: true, source: 'both' },

  // ── TLS ─────────────────────────────────────────────────────────────────────
  { key: 'tls_version', label: 'TLS Version', type: 'string', group: 'tls', source: 'access' },
  { key: 'tls_cipher_suite', label: 'TLS Cipher Suite', type: 'string', group: 'tls', source: 'access' },
  { key: 'sni', label: 'SNI', type: 'string', group: 'tls', source: 'both' },
  { key: 'mtls', label: 'mTLS', type: 'boolean', group: 'tls', source: 'access' },
  { key: 'tls_fingerprint', label: 'TLS Fingerprint (MD5)', type: 'string', group: 'tls', source: 'both' },
  { key: 'ja4_tls_fingerprint', label: 'JA4 TLS Fingerprint', type: 'string', group: 'tls', source: 'both' },

  // ── META ────────────────────────────────────────────────────────────────────
  { key: 'sample_rate', label: 'Sample Rate', type: 'numeric', group: 'meta', source: 'access' },
  { key: 'connection_state', label: 'Connection State', type: 'string', group: 'meta', source: 'access' },
  { key: 'lb_port', label: 'LB Port', type: 'string', group: 'meta', source: 'access' },
  { key: 'src_port', label: 'Source Port', type: 'string', group: 'meta', source: 'both' },
  { key: 'namespace', label: 'Namespace', type: 'string', group: 'meta', source: 'both' },
  { key: 'tenant', label: 'Tenant', type: 'string', group: 'meta', source: 'both' },
  { key: 'app', label: 'App', type: 'string', group: 'meta', source: 'both' },
  { key: 'stream', label: 'Stream', type: 'string', group: 'meta', source: 'both' },
  { key: 'req_id', label: 'Request ID', type: 'string', group: 'meta', source: 'both' },
  { key: 'messageid', label: 'Message ID', type: 'string', group: 'meta', source: 'both' },
  { key: 'vhost_id', label: 'VHost ID', type: 'string', group: 'meta', source: 'security' },
  { key: 'connected_time', label: 'Connected Time', type: 'string', group: 'meta', source: 'access' },
  { key: 'terminated_time', label: 'Terminated Time', type: 'string', group: 'meta', source: 'access' },
  { key: 'timeseries_enabled', label: 'Timeseries Enabled', type: 'boolean', group: 'meta', source: 'access' },
];

// ═══════════════════════════════════════════════════════════════════════════════
// PRE-FETCH FILTER FIELDS — fields available for server-side query filtering
// ═══════════════════════════════════════════════════════════════════════════════
export const PRE_FETCH_FILTER_FIELDS = [
  // Common (both)
  'vh_name', 'domain', 'authority', 'src_ip', 'method', 'rsp_code', 'rsp_code_class',
  'country', 'region', 'city', 'asn', 'src_site', 'site', 'user', 'api_endpoint',
  'app_type', 'browser_type', 'device_type',
  // Access log specific
  'dst', 'dst_ip', 'dst_site', 'dst_port', 'waf_action', 'bot_class', 'scheme',
  'proxy_type', 'tls_version', 'protocol', 'sni', 'rsp_code_details',
  // Security event specific
  'sec_event_type', 'sec_event_name', 'action', 'recommended_action',
  'enforcement_mode', 'waf_mode', 'app_firewall_name',
  'violation_rating', 'req_risk', 'attack_types',
  'bot_info.classification', 'bot_info.type', 'bot_info.name',
];

/**
 * Get field definitions filtered by the selected log source.
 * - 'access': shows access-only + both fields
 * - 'security': shows security-only + both fields
 * - 'both': shows all fields
 */
export function getFieldsForSource(source: LogSource): FieldDefinition[] {
  return FIELD_DEFINITIONS.filter(f => {
    const s = f.source || 'access';
    if (source === 'both') return true;
    return s === source || s === 'both';
  });
}

export function getNumericFieldsForSource(source: LogSource): FieldDefinition[] {
  return getFieldsForSource(source).filter(f => f.type === 'numeric');
}

export function getStringFieldsForSource(source: LogSource): FieldDefinition[] {
  return getFieldsForSource(source).filter(f => f.type === 'string');
}

export function getBooleanFieldsForSource(source: LogSource): FieldDefinition[] {
  return getFieldsForSource(source).filter(f => f.type === 'boolean');
}

export const NUMERIC_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'numeric');
export const STRING_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'string');
export const BOOLEAN_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'boolean');

export const FIELD_GROUP_LABELS: Record<string, string> = {
  timing: 'Timing',
  request: 'Request',
  response: 'Response',
  routing: 'Routing',
  security: 'Security & Policy',
  security_event: 'Security Events',
  geo: 'Geography',
  tls: 'TLS / Fingerprint',
  meta: 'Metadata',
};
