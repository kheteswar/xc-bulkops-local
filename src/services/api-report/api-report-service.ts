// ============================================================
// API Report Dashboard – Service Layer
// ============================================================
import { apiClient } from '../api';
import type {
  ApiEndpointStats,
  ApiEndpointRow,
  SwaggerEndpoint,
  ApiReportResults,
  FetchProgress,
} from './types';
import { COLUMN_MAPPING, COLUMN_KEYS } from './types';

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function getQueryParams(days: number): string {
  const now = new Date();
  const end = now.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  const start = new Date(now.getTime() - days * 86400000)
    .toISOString()
    .replace(/\.\d{3}Z$/, '.000Z');
  return `?api_endpoint_info_request=1&start_time=${start}&end_time=${end}`;
}

/** Resolve nested dot-notation keys like "risk_score.score" */
function resolveNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const keys = path.split('.');
  let current: unknown = obj;
  for (const key of keys) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function formatValue(column: string, value: unknown): string {
  if (value === undefined || value === null) return '—';

  if (column === 'Last Updated' && typeof value === 'string' && value) {
    try {
      const dt = new Date(value.replace('Z', '+00:00'));
      return dt.toLocaleString(undefined, {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return String(value);
    }
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return '—';
    if (value.every((x) => typeof x === 'object' && x !== null)) {
      return JSON.stringify(value);
    }
    return value.map(String).join(', ');
  }

  const s = String(value);
  return s || '—';
}

// ------------------------------------------------------------------
// 1. Namespace Stats
// ------------------------------------------------------------------

export async function fetchNamespaceStats(namespace: string): Promise<ApiEndpointStats> {
  const data = await apiClient.post<Record<string, unknown>>(
    `/api/ml/data/namespaces/${namespace}/api_endpoints/stats`,
    {
      namespace,
      vhosts_filter: [],
      vhosts_types_filter: ['HTTP_LOAD_BALANCER', 'CDN_LOAD_BALANCER'],
    },
  );
  return {
    scope: `Namespace: ${namespace}`,
    total_endpoints: (data.total_endpoints as number) ?? 0,
    discovered: (data.discovered as number) ?? 0,
    inventory: (data.inventory as number) ?? 0,
    shadow: (data.shadow as number) ?? 0,
    pii_detected: (data.pii_detected as number) ?? 0,
  };
}

// ------------------------------------------------------------------
// 2. Per-LB Stats
// ------------------------------------------------------------------

export async function fetchLBStats(
  namespace: string,
  lbNames: string[],
  onProgress?: (p: FetchProgress) => void,
): Promise<ApiEndpointStats[]> {
  const results: ApiEndpointStats[] = [];

  for (let i = 0; i < lbNames.length; i++) {
    const lb = lbNames[i];
    onProgress?.({
      phase: 'stats',
      current: i + 1,
      total: lbNames.length,
      lbName: lb,
      message: `Fetching stats for ${lb}`,
    });

    try {
      const data = await apiClient.post<Record<string, unknown>>(
        `/api/ml/data/namespaces/${namespace}/api_endpoints/stats`,
        {
          namespace,
          vhosts_filter: [`ves-io-http-loadbalancer-${lb}`],
          vhosts_types_filter: [],
        },
      );
      results.push({
        scope: lb,
        total_endpoints: (data.total_endpoints as number) ?? 0,
        discovered: (data.discovered as number) ?? 0,
        inventory: (data.inventory as number) ?? 0,
        shadow: (data.shadow as number) ?? 0,
        pii_detected: (data.pii_detected as number) ?? 0,
      });
    } catch {
      results.push({
        scope: lb,
        total_endpoints: 0,
        discovered: 0,
        inventory: 0,
        shadow: 0,
        pii_detected: 0,
      });
    }
  }

  return results;
}

// ------------------------------------------------------------------
// 3. Swagger / Learnt Schema (parsed server-side)
// ------------------------------------------------------------------

export async function fetchSwaggerSpecs(
  namespace: string,
  lbNames: string[],
  onProgress?: (p: FetchProgress) => void,
): Promise<SwaggerEndpoint[]> {
  const allEndpoints: SwaggerEndpoint[] = [];

  for (let i = 0; i < lbNames.length; i++) {
    const lb = lbNames[i];
    onProgress?.({
      phase: 'swagger',
      current: i + 1,
      total: lbNames.length,
      lbName: lb,
      message: `Downloading swagger spec for ${lb}`,
    });

    try {
      const tenant = apiClient.getTenant();
      const token = apiClient.getToken();
      if (!tenant || !token) throw new Error('Not connected');

      const resp = await fetch('/api/proxy/swagger-parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant, token, namespace, lbName: lb }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        allEndpoints.push({
          lb,
          fqdn: '-',
          path: (errData as Record<string, string>).error || `Error ${resp.status}`,
          method: '-',
          contentType: '-',
        });
        continue;
      }

      const data = await resp.json() as { specs: Array<{ fqdn: string; endpoints: Array<{ path: string; method: string; contentType: string }> }> };

      if (!data.specs || data.specs.length === 0) {
        allEndpoints.push({
          lb, fqdn: '-', path: 'No discovered APIs', method: '-', contentType: '-',
        });
        continue;
      }

      for (const spec of data.specs) {
        for (const ep of spec.endpoints) {
          allEndpoints.push({
            lb,
            fqdn: spec.fqdn || '-',
            path: ep.path,
            method: ep.method,
            contentType: ep.contentType || '-',
          });
        }
      }
    } catch (err: unknown) {
      allEndpoints.push({
        lb,
        fqdn: '-',
        path: `Error: ${err instanceof Error ? err.message : String(err)}`,
        method: '-',
        contentType: '-',
      });
    }
  }

  return allEndpoints;
}

// ------------------------------------------------------------------
// 4. Detailed Endpoint Data
// ------------------------------------------------------------------

export async function fetchEndpointDetails(
  namespace: string,
  lbNames: string[],
  days: number,
  onProgress?: (p: FetchProgress) => void,
): Promise<ApiEndpointRow[]> {
  const allRows: ApiEndpointRow[] = [];

  for (let i = 0; i < lbNames.length; i++) {
    const lb = lbNames[i];
    onProgress?.({
      phase: 'endpoints',
      current: i + 1,
      total: lbNames.length,
      lbName: lb,
      message: `Fetching API endpoints for ${lb}`,
    });

    try {
      const endpoint = `/api/ml/data/namespaces/${namespace}/virtual_hosts/ves-io-http-loadbalancer-${lb}/api_endpoints${getQueryParams(days)}`;
      console.log(`[APIReport] Fetching endpoints for ${lb}:`, endpoint);
      const data = await apiClient.get<Record<string, unknown>>(endpoint);
      console.log(`[APIReport] Response for ${lb}:`, { keys: Object.keys(data || {}), type: typeof data });

      let items: Record<string, unknown>[] = [];
      if (data.apiep_list && Array.isArray(data.apiep_list)) {
        items = data.apiep_list;
      } else if (Array.isArray(data)) {
        items = data as unknown as Record<string, unknown>[];
      } else {
        // Try to find any array in the response that looks like endpoint data
        for (const [key, val] of Object.entries(data || {})) {
          if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
            console.log(`[APIReport] Found endpoint array under key "${key}" (${val.length} items)`);
            items = val as Record<string, unknown>[];
            break;
          }
        }
      }

      console.log(`[APIReport] ${lb}: found ${items.length} endpoints`);

      for (const item of items) {
        const row: ApiEndpointRow = { lb };
        for (const [column, responseKey] of Object.entries(COLUMN_MAPPING)) {
          if (responseKey.includes('.')) {
            const nested = resolveNestedValue(item, responseKey);
            row[column] = formatValue(column, nested);
          } else if (responseKey in item) {
            row[column] = formatValue(column, item[responseKey]);
          } else {
            row[column] = '—';
          }
        }
        allRows.push(row);
      }
    } catch (err) {
      console.error(`[APIReport] Failed to fetch endpoints for ${lb}:`, err);
    }
  }

  return allRows;
}

// ------------------------------------------------------------------
// 5. Full Report Orchestrator
// ------------------------------------------------------------------

export async function runFullReport(
  namespace: string,
  lbNames: string[],
  days: number,
  onProgress?: (p: FetchProgress) => void,
): Promise<ApiReportResults> {
  // 1. Namespace stats
  onProgress?.({ phase: 'stats', current: 0, total: lbNames.length, message: 'Fetching namespace stats...' });
  let nsStats: ApiEndpointStats | null = null;
  try {
    nsStats = await fetchNamespaceStats(namespace);
  } catch { /* non-critical */ }

  // 2. Per-LB stats
  const lbStats = await fetchLBStats(namespace, lbNames, onProgress);

  // 3. Swagger specs
  const swaggerEndpoints = await fetchSwaggerSpecs(namespace, lbNames, onProgress);

  // 4. Detailed endpoint data
  const endpointRows = await fetchEndpointDetails(namespace, lbNames, days, onProgress);

  return { nsStats, lbStats, swaggerEndpoints, endpointRows };
}

// ------------------------------------------------------------------
// 6. Excel Export
// ------------------------------------------------------------------

export async function exportAsExcel(
  results: ApiReportResults,
  namespace: string,
): Promise<void> {
  const XLSX = await import('xlsx');
  const wb = XLSX.utils.book_new();

  // Sheet 1: Stats Overview
  const statsRows = [
    ...(results.nsStats
      ? [{
          Scope: results.nsStats.scope,
          'Total Endpoints': results.nsStats.total_endpoints,
          Discovered: results.nsStats.discovered,
          Inventory: results.nsStats.inventory,
          Shadow: results.nsStats.shadow,
          'PII Detected': results.nsStats.pii_detected,
        }]
      : []),
    ...results.lbStats.map((s) => ({
      Scope: s.scope,
      'Total Endpoints': s.total_endpoints,
      Discovered: s.discovered,
      Inventory: s.inventory,
      Shadow: s.shadow,
      'PII Detected': s.pii_detected,
    })),
  ];
  if (statsRows.length > 0) {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(statsRows), 'Stats Overview');
  }

  // Sheet 2: Swagger / Learnt Schema
  if (results.swaggerEndpoints.length > 0) {
    const swaggerRows = results.swaggerEndpoints.map((e) => ({
      'Load Balancer': e.lb,
      FQDN: e.fqdn,
      'API Endpoint': e.path,
      Method: e.method,
      'Content Type': e.contentType,
    }));
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(swaggerRows), 'Swagger Specs');
  }

  // Sheet 3: Detailed Endpoints
  if (results.endpointRows.length > 0) {
    // Group by LB for readability
    const detailRows = results.endpointRows.map((r) => {
      const row: Record<string, string | number | undefined> = { 'Load Balancer': r.lb };
      for (const col of COLUMN_KEYS) {
        row[col] = r[col];
      }
      return row;
    });
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(detailRows), 'API Endpoints');
  }

  const buf = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([buf], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${namespace}_api_report.xlsx`;
  a.click();
  URL.revokeObjectURL(url);
}
