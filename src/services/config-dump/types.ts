// ═══════════════════════════════════════════════════════════════════════════
// CONFIG DUMP - TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface ObjectTypeDefinition {
  id: string;
  label: string;
  category: string;
  apiResource: string;           // plural resource name for list/get
  childRefs: ChildRefDefinition[];
}

export interface ChildRefDefinition {
  /** Dot-path to the reference(s) in the parent spec, supports [] array wildcards */
  path: string;
  /** The object type id this reference points to */
  targetType: string;
  /** Whether the path resolves to an array of refs */
  isArray?: boolean;
  /** Label shown in the UI tree */
  label: string;
}

export interface FetchedObject {
  /** Object type id */
  type: string;
  /** Object name */
  name: string;
  /** Namespace */
  namespace: string;
  /** Full raw JSON config */
  config: any;
  /** Resolved child objects */
  children: FetchedChild[];
  /** Error message if fetch failed but was retried */
  fetchError?: string;
}

export interface FetchedChild {
  /** Label for display */
  label: string;
  /** The child object type */
  type: string;
  /** Resolved objects */
  objects: FetchedObject[];
}

export interface DumpProgress {
  phase: 'listing' | 'fetching' | 'resolving' | 'done' | 'cancelled';
  message: string;
  current: number;
  total: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// FETCH OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface FetchOptions {
  /** AbortSignal for cancellation */
  signal?: AbortSignal;
  /** Child type ids to exclude from resolution */
  excludeChildTypes?: Set<string>;
  /** Progress callback */
  onProgress?: (p: DumpProgress) => void;
}

// ═══════════════════════════════════════════════════════════════════════════
// RELATIONSHIP GRAPH
// ═══════════════════════════════════════════════════════════════════════════

export interface GraphNode {
  id: string;           // "type:ns/name"
  type: string;
  name: string;
  namespace: string;
  /** How many parent objects reference this node */
  parentCount: number;
  /** Whether this is a root-level (selected) object */
  isRoot: boolean;
}

export interface GraphEdge {
  source: string;       // GraphNode.id
  target: string;       // GraphNode.id
  label: string;        // ChildRef label
}

export interface RelationshipGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ═══════════════════════════════════════════════════════════════════════════
// TYPE COLORS — shared across graph, table, tree and matrix views
// ═══════════════════════════════════════════════════════════════════════════

export const TYPE_COLORS: Record<string, string> = {
  http_loadbalancer: '#3b82f6',   // blue
  tcp_loadbalancer: '#6366f1',    // indigo
  cdn_loadbalancer: '#8b5cf6',    // violet
  origin_pool: '#10b981',         // emerald
  healthcheck: '#14b8a6',         // teal
  app_firewall: '#ef4444',        // red
  waf_exclusion_policy: '#f97316', // orange
  service_policy: '#f59e0b',      // amber
  rate_limiter: '#eab308',        // yellow
  rate_limiter_policy: '#84cc16', // lime
  forward_proxy_policy: '#22c55e', // green
  user_identification: '#06b6d4', // cyan
  malicious_user_mitigation: '#ec4899', // pink
  app_type: '#a855f7',           // purple
  app_setting: '#d946ef',        // fuchsia
  api_definition: '#0ea5e9',     // sky
  ip_prefix_set: '#64748b',      // slate
  certificate: '#f43f5e',        // rose
  alert_policy: '#fb923c',       // orange-400
  alert_receiver: '#fdba74',     // orange-300
  global_log_receiver: '#fbbf24', // amber-400
  dns_zone: '#2dd4bf',           // teal-400
  network_policy: '#94a3b8',     // slate-400
  virtual_site: '#a78bfa',       // violet-400
};

export function getTypeColor(type: string): string {
  return TYPE_COLORS[type] || '#64748b';
}

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT TYPE REGISTRY
// ═══════════════════════════════════════════════════════════════════════════

export const OBJECT_CATEGORIES = [
  'Load Balancers',
  'Pools & Health',
  'Security - WAF',
  'Security - Policies',
  'Security - Bot & DDoS',
  'Certificates & TLS',
  'Alerting & Logging',
  'Networking',
  'App Security',
  'DNS',
] as const;

export const OBJECT_TYPES: ObjectTypeDefinition[] = [
  // ── Load Balancers ──────────────────────────────────────────────
  {
    id: 'http_loadbalancer',
    label: 'HTTP Load Balancer',
    category: 'Load Balancers',
    apiResource: 'http_loadbalancers',
    childRefs: [
      { path: 'spec.app_firewall', targetType: 'app_firewall', label: 'WAF Policy' },
      { path: 'spec.default_route_pools[].pool', targetType: 'origin_pool', isArray: true, label: 'Origin Pools' },
      { path: 'spec.routes[].simple_route.origin_pools[].pool', targetType: 'origin_pool', isArray: true, label: 'Route Origin Pools' },
      { path: 'spec.routes[].redirect_route.origin_pools[].pool', targetType: 'origin_pool', isArray: true, label: 'Redirect Route Pools' },
      { path: 'spec.active_service_policies.policies[]', targetType: 'service_policy', isArray: true, label: 'Service Policies' },
      { path: 'spec.rate_limiter', targetType: 'rate_limiter', label: 'Rate Limiter' },
      { path: 'spec.rate_limit.policies[]', targetType: 'rate_limiter_policy', isArray: true, label: 'Rate Limiter Policies' },
      { path: 'spec.user_identification', targetType: 'user_identification', label: 'User Identification' },
      { path: 'spec.malicious_user_mitigation', targetType: 'malicious_user_mitigation', label: 'Malicious User Mitigation' },
      { path: 'spec.multi_lb_app', targetType: 'app_type', label: 'App Type' },
      { path: 'spec.bot_defense.policy', targetType: 'app_type', label: 'Bot Defense App Type' },
      { path: 'spec.api_definition', targetType: 'api_definition', label: 'API Definition' },
      { path: 'spec.waf_exclusion_rules', targetType: 'waf_exclusion_policy', label: 'WAF Exclusion Policy' },
      { path: 'spec.ip_reputation.ip_threat_categories[].ip_prefix_set', targetType: 'ip_prefix_set', isArray: true, label: 'IP Prefix Sets' },
    ],
  },
  {
    id: 'tcp_loadbalancer',
    label: 'TCP Load Balancer',
    category: 'Load Balancers',
    apiResource: 'tcp_loadbalancers',
    childRefs: [
      { path: 'spec.origin_pools[].pool', targetType: 'origin_pool', isArray: true, label: 'Origin Pools' },
      { path: 'spec.active_service_policies.policies[]', targetType: 'service_policy', isArray: true, label: 'Service Policies' },
    ],
  },
  {
    id: 'cdn_loadbalancer',
    label: 'CDN Load Balancer',
    category: 'Load Balancers',
    apiResource: 'cdn_loadbalancers',
    childRefs: [
      { path: 'spec.origin_pool', targetType: 'origin_pool', label: 'Origin Pool' },
      { path: 'spec.app_firewall', targetType: 'app_firewall', label: 'WAF Policy' },
    ],
  },

  // ── Pools & Health ──────────────────────────────────────────────
  {
    id: 'origin_pool',
    label: 'Origin Pool',
    category: 'Pools & Health',
    apiResource: 'origin_pools',
    childRefs: [
      { path: 'spec.healthcheck[]', targetType: 'healthcheck', isArray: true, label: 'Health Checks' },
    ],
  },
  {
    id: 'healthcheck',
    label: 'Health Check',
    category: 'Pools & Health',
    apiResource: 'healthchecks',
    childRefs: [],
  },

  // ── Security - WAF ──────────────────────────────────────────────
  {
    id: 'app_firewall',
    label: 'Application Firewall (WAF)',
    category: 'Security - WAF',
    apiResource: 'app_firewalls',
    childRefs: [],
  },
  {
    id: 'waf_exclusion_policy',
    label: 'WAF Exclusion Policy',
    category: 'Security - WAF',
    apiResource: 'waf_exclusion_policys',
    childRefs: [],
  },

  // ── Security - Policies ─────────────────────────────────────────
  {
    id: 'service_policy',
    label: 'Service Policy',
    category: 'Security - Policies',
    apiResource: 'service_policys',
    childRefs: [
      { path: 'spec.rule_list.rules[].spec.rate_limiter', targetType: 'rate_limiter', isArray: true, label: 'Rate Limiters' },
      { path: 'spec.rule_list.rules[].spec.ip_prefix_set', targetType: 'ip_prefix_set', isArray: true, label: 'IP Prefix Sets' },
    ],
  },
  {
    id: 'rate_limiter',
    label: 'Rate Limiter',
    category: 'Security - Policies',
    apiResource: 'rate_limiters',
    childRefs: [],
  },
  {
    id: 'rate_limiter_policy',
    label: 'Rate Limiter Policy',
    category: 'Security - Policies',
    apiResource: 'rate_limiter_policys',
    childRefs: [],
  },
  {
    id: 'forward_proxy_policy',
    label: 'Forward Proxy Policy',
    category: 'Security - Policies',
    apiResource: 'forward_proxy_policys',
    childRefs: [],
  },

  // ── Security - Bot & DDoS ──────────────────────────────────────
  {
    id: 'user_identification',
    label: 'User Identification Policy',
    category: 'Security - Bot & DDoS',
    apiResource: 'user_identification_policys',
    childRefs: [],
  },
  {
    id: 'malicious_user_mitigation',
    label: 'Malicious User Mitigation',
    category: 'Security - Bot & DDoS',
    apiResource: 'malicious_user_mitigations',
    childRefs: [],
  },

  // ── Certificates & TLS ─────────────────────────────────────────
  {
    id: 'certificate',
    label: 'Certificate',
    category: 'Certificates & TLS',
    apiResource: 'certificates',
    childRefs: [],
  },

  // ── Alerting & Logging ─────────────────────────────────────────
  {
    id: 'alert_policy',
    label: 'Alert Policy',
    category: 'Alerting & Logging',
    apiResource: 'alert_policys',
    childRefs: [
      { path: 'spec.receivers[]', targetType: 'alert_receiver', isArray: true, label: 'Alert Receivers' },
    ],
  },
  {
    id: 'alert_receiver',
    label: 'Alert Receiver',
    category: 'Alerting & Logging',
    apiResource: 'alert_receivers',
    childRefs: [],
  },
  {
    id: 'global_log_receiver',
    label: 'Global Log Receiver',
    category: 'Alerting & Logging',
    apiResource: 'global_log_receivers',
    childRefs: [],
  },

  // ── Networking ──────────────────────────────────────────────────
  {
    id: 'virtual_site',
    label: 'Virtual Site',
    category: 'Networking',
    apiResource: 'virtual_sites',
    childRefs: [],
  },
  {
    id: 'ip_prefix_set',
    label: 'IP Prefix Set',
    category: 'Networking',
    apiResource: 'ip_prefix_sets',
    childRefs: [],
  },
  {
    id: 'network_policy',
    label: 'Network Policy',
    category: 'Networking',
    apiResource: 'network_policys',
    childRefs: [],
  },

  // ── App Security ───────────────────────────────────────────────
  {
    id: 'app_type',
    label: 'App Type',
    category: 'App Security',
    apiResource: 'app_types',
    childRefs: [],
  },
  {
    id: 'app_setting',
    label: 'App Setting',
    category: 'App Security',
    apiResource: 'app_settings',
    childRefs: [],
  },
  {
    id: 'api_definition',
    label: 'API Definition',
    category: 'App Security',
    apiResource: 'api_definitions',
    childRefs: [],
  },

  // ── DNS ─────────────────────────────────────────────────────────
  {
    id: 'dns_zone',
    label: 'DNS Zone',
    category: 'DNS',
    apiResource: 'dns_zones',
    childRefs: [],
  },
];
