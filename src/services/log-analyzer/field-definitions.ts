import type { FieldDefinition } from './types';

export const FIELD_DEFINITIONS: FieldDefinition[] = [
  // ── Timing (numeric) ──────────────────────────────────────────────
  { key: 'total_duration_seconds', label: 'Total Duration (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_first_upstream_rx_byte', label: 'TTFB Upstream RX (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_last_upstream_rx_byte', label: 'TTLB Upstream RX (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_first_upstream_tx_byte', label: 'TTFB Upstream TX (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_first_downstream_tx_byte', label: 'TTFB Downstream TX (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_last_downstream_tx_byte', label: 'TTLB Downstream TX (s)', type: 'numeric', group: 'timing' },
  { key: 'time_to_last_rx_byte', label: 'Time to Last RX Byte (s)', type: 'numeric', group: 'timing' },
  { key: 'rtt_upstream_seconds', label: 'RTT Upstream (s)', type: 'numeric', group: 'timing', parseAsNumber: true },
  { key: 'rtt_downstream_seconds', label: 'RTT Downstream (s)', type: 'numeric', group: 'timing', parseAsNumber: true },
  { key: 'duration_with_data_tx_delay', label: 'Duration w/ Data TX Delay', type: 'numeric', group: 'timing', parseAsNumber: true },
  { key: 'duration_with_no_data_tx_delay', label: 'Duration w/o Data TX Delay', type: 'numeric', group: 'timing', parseAsNumber: true },

  // ── Request ────────────────────────────────────────────────────────
  { key: 'method', label: 'HTTP Method', type: 'string', group: 'request' },
  { key: 'req_path', label: 'Request Path', type: 'string', group: 'request' },
  { key: 'original_path', label: 'Original Path', type: 'string', group: 'request' },
  { key: 'authority', label: 'Authority', type: 'string', group: 'request' },
  { key: 'domain', label: 'Domain', type: 'string', group: 'request' },
  { key: 'original_authority', label: 'Original Authority', type: 'string', group: 'request' },
  { key: 'scheme', label: 'Scheme', type: 'string', group: 'request' },
  { key: 'protocol', label: 'Protocol', type: 'string', group: 'request' },
  { key: 'user_agent', label: 'User Agent', type: 'string', group: 'request' },
  { key: 'req_size', label: 'Request Size (bytes)', type: 'numeric', group: 'request', parseAsNumber: true },
  { key: 'browser_type', label: 'Browser Type', type: 'string', group: 'request' },
  { key: 'device_type', label: 'Device Type', type: 'string', group: 'request' },
  { key: 'app_type', label: 'App Type', type: 'string', group: 'request' },

  // ── Response ───────────────────────────────────────────────────────
  { key: 'rsp_code', label: 'Response Code', type: 'string', group: 'response' },
  { key: 'rsp_code_class', label: 'Response Code Class', type: 'string', group: 'response' },
  { key: 'rsp_code_details', label: 'Response Code Details', type: 'string', group: 'response' },
  { key: 'rsp_size', label: 'Response Size (bytes)', type: 'numeric', group: 'response', parseAsNumber: true },
  { key: 'response_flags', label: 'Response Flags', type: 'string', group: 'response' },

  // ── Routing ────────────────────────────────────────────────────────
  { key: 'dst', label: 'Destination', type: 'string', group: 'routing' },
  { key: 'dst_ip', label: 'Destination IP', type: 'string', group: 'routing' },
  { key: 'dst_port', label: 'Destination Port', type: 'string', group: 'routing' },
  { key: 'dst_site', label: 'Destination Site', type: 'string', group: 'routing' },
  { key: 'dst_instance', label: 'Destination Instance', type: 'string', group: 'routing' },
  { key: 'src_site', label: 'Source Site', type: 'string', group: 'routing' },
  { key: 'src_instance', label: 'Source Instance', type: 'string', group: 'routing' },
  { key: 'vh_name', label: 'Virtual Host (LB)', type: 'string', group: 'routing' },
  { key: 'vh_type', label: 'VH Type', type: 'string', group: 'routing' },
  { key: 'proxy_type', label: 'Proxy Type', type: 'string', group: 'routing' },
  { key: 'site', label: 'Site', type: 'string', group: 'routing' },
  { key: 'cluster_name', label: 'Cluster Name', type: 'string', group: 'routing' },
  { key: 'hostname', label: 'Hostname', type: 'string', group: 'routing' },

  // ── Security ───────────────────────────────────────────────────────
  { key: 'src_ip', label: 'Source IP', type: 'string', group: 'security' },
  { key: 'x_forwarded_for', label: 'X-Forwarded-For', type: 'string', group: 'security' },
  { key: 'waf_action', label: 'WAF Action', type: 'string', group: 'security' },
  { key: 'bot_class', label: 'Bot Class', type: 'string', group: 'security' },
  { key: 'has_sec_event', label: 'Has Security Event', type: 'boolean', group: 'security' },
  { key: 'api_endpoint', label: 'API Endpoint', type: 'string', group: 'security' },
  { key: 'user', label: 'User Identifier', type: 'string', group: 'security' },

  // ── Geo ────────────────────────────────────────────────────────────
  { key: 'country', label: 'Country', type: 'string', group: 'geo' },
  { key: 'region', label: 'Region', type: 'string', group: 'geo' },
  { key: 'city', label: 'City', type: 'string', group: 'geo' },
  { key: 'asn', label: 'ASN', type: 'string', group: 'geo' },
  { key: 'as_org', label: 'AS Organization', type: 'string', group: 'geo' },
  { key: 'as_number', label: 'AS Number', type: 'string', group: 'geo' },
  { key: 'network', label: 'Network', type: 'string', group: 'geo' },
  { key: 'latitude', label: 'Latitude', type: 'numeric', group: 'geo', parseAsNumber: true },
  { key: 'longitude', label: 'Longitude', type: 'numeric', group: 'geo', parseAsNumber: true },

  // ── TLS ────────────────────────────────────────────────────────────
  { key: 'tls_version', label: 'TLS Version', type: 'string', group: 'tls' },
  { key: 'tls_cipher_suite', label: 'TLS Cipher Suite', type: 'string', group: 'tls' },
  { key: 'sni', label: 'SNI', type: 'string', group: 'tls' },
  { key: 'mtls', label: 'mTLS', type: 'boolean', group: 'tls' },
  { key: 'tls_fingerprint', label: 'TLS Fingerprint', type: 'string', group: 'tls' },
  { key: 'ja4_tls_fingerprint', label: 'JA4 TLS Fingerprint', type: 'string', group: 'tls' },

  // ── Meta ───────────────────────────────────────────────────────────
  { key: 'sample_rate', label: 'Sample Rate', type: 'numeric', group: 'meta' },
  { key: 'connection_state', label: 'Connection State', type: 'string', group: 'meta' },
  { key: 'lb_port', label: 'LB Port', type: 'string', group: 'meta' },
  { key: 'src_port', label: 'Source Port', type: 'string', group: 'meta' },
  { key: 'namespace', label: 'Namespace', type: 'string', group: 'meta' },
  { key: 'tenant', label: 'Tenant', type: 'string', group: 'meta' },
  { key: 'node_id', label: 'Node ID', type: 'string', group: 'meta' },
  { key: 'app', label: 'App', type: 'string', group: 'meta' },
];

export const PRE_FETCH_FILTER_FIELDS = [
  'vh_name', 'domain', 'authority', 'src_ip', 'dst', 'dst_ip', 'dst_site',
  'src_site', 'method', 'rsp_code', 'rsp_code_class', 'country', 'region',
  'waf_action', 'bot_class', 'scheme', 'proxy_type', 'tls_version',
  'protocol', 'site', 'api_endpoint', 'sni', 'app_type', 'device_type',
];

export const NUMERIC_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'numeric');
export const STRING_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'string');
export const BOOLEAN_FIELDS = FIELD_DEFINITIONS.filter(f => f.type === 'boolean');

export const FIELD_GROUP_LABELS: Record<string, string> = {
  timing: 'Timing',
  request: 'Request',
  response: 'Response',
  routing: 'Routing',
  security: 'Security',
  geo: 'Geography',
  tls: 'TLS',
  meta: 'Metadata',
};
