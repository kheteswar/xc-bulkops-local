// ============================================================
// API Report Dashboard – Type Definitions
// ============================================================

/** Stats for a namespace or individual load balancer */
export interface ApiEndpointStats {
  scope: string;                  // "Namespace: xyz" or LB name
  total_endpoints: number;
  discovered: number;
  inventory: number;
  shadow: number;
  pii_detected: number;
}

/** Column mapping for the detailed endpoint export (mirrors Python COLUMN_MAPPING) */
export const COLUMN_MAPPING: Record<string, string> = {
  'API Endpoint':          'collapsed_url',
  'Method':                'method',
  'Sensitive Data':        'sensitive_data_types',
  'Threat Level':          'security_risk',
  'Domains':               'domains',
  'API Category':          'category',
  'Discovery Source':      'engines',
  'Risk Score':            'risk_score.score',
  'API Compliance':        'compliances',
  'Request Rate':          'req_rate',
  'Requests':              'requests_count',
  'Average Latency':       'avg_latency',
  'Errors':                'err_rsp_count',
  'Authentication State':  'authentication_state',
  'Authentication Type':   'authentication_types',
  'API Attributes':        'attributes',
  'Schema Status':         'schema_status',
  'Sensitive Data Location': 'sensitive_data_location',
  'Groups':                'api_groups',
  'Last Updated':          'access_discovery_time',
  'Last Tested':           'last_tested',
};

export const COLUMN_KEYS = Object.keys(COLUMN_MAPPING);

/** A single parsed API endpoint row from the detail API */
export interface ApiEndpointRow {
  lb: string;
  [column: string]: string | number | undefined;
}

/** A parsed swagger endpoint entry */
export interface SwaggerEndpoint {
  lb: string;
  fqdn: string;
  path: string;
  method: string;
  contentType: string;
}

/** Progress callback for multi-LB operations */
export interface FetchProgress {
  phase: 'stats' | 'swagger' | 'endpoints';
  current: number;
  total: number;
  lbName?: string;
  message: string;
}

/** Aggregated results from the full report run */
export interface ApiReportResults {
  nsStats: ApiEndpointStats | null;
  lbStats: ApiEndpointStats[];
  swaggerEndpoints: SwaggerEndpoint[];
  endpointRows: ApiEndpointRow[];
}
