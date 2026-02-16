import type { Credentials, Namespace, LoadBalancer, WAFPolicy, OriginPool, AppType, AppSetting, VirtualSite, UserIdentificationPolicy, AlertReceiver, AlertPolicy, CDNLoadBalancer, CDNCacheRule, IpPrefixSet, ServicePolicy, Certificate } from '../types';

// Proxy endpoint - same server, no need for separate URL
const PROXY_ENDPOINT = '/api/proxy';

class F5XCApiClient {
  private tenant: string | null = null;
  private apiToken: string | null = null;

  init(tenant: string, apiToken: string) {
    this.tenant = tenant;
    this.apiToken = apiToken;
  }

  clear() {
    this.tenant = null;
    this.apiToken = null;
  }

  isInitialized(): boolean {
    return Boolean(this.tenant && this.apiToken);
  }

  getTenant(): string | null {
    return this.tenant;
  }

  private async proxyRequest<T>(endpoint: string, method = 'GET', body?: unknown): Promise<T> {
    if (!this.tenant || !this.apiToken) {
      throw new Error('API client not initialized');
    }

    const response = await fetch(PROXY_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: this.tenant,
        token: this.apiToken,
        endpoint,
        method,
        body,
      }),
    });

    // Attempt to parse JSON response
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.indexOf('application/json') !== -1) {
      data = await response.json();
    } else {
      // Handle non-JSON responses (usually generic errors)
      if (!response.ok) {
         throw new Error(`API Error: ${response.status} ${response.statusText}`);
      }
      return {} as T; 
    }

    // Check for HTTP errors or API-specific error fields
    if (!response.ok) {
      // Prioritize specific API error message
      const errorMessage = data.message || data.error || `API Error: ${response.statusText}`;
      throw new Error(errorMessage);
    }
    
    // Some APIs return 200 OK but contain an error field
    if (data.error) {
      throw new Error(data.error);
    }

    return data as T;
  }

  // Inside src/services/api.ts, add this method to the F5XCApiClient class:

async requestExternal<T>(tenant: string, token: string, endpoint: string, method = 'GET'): Promise<T> {
  const response = await fetch(PROXY_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tenant,
      token,
      endpoint,
      method,
    }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.message || `External API Error: ${response.statusText}`);
  }

  return response.json();
}

  async get<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'GET');
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.proxyRequest<T>(path, 'POST', body);
  }

  async put<T>(path: string, body: unknown): Promise<T> {
    return this.proxyRequest<T>(path, 'PUT', body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'DELETE');
  }

  // --- Namespace APIs ---
  async getNamespaces(): Promise<{ items: Namespace[] }> {
    return this.get('/api/web/namespaces');
  }

  // --- Load Balancer APIs ---
  async getLoadBalancers(namespace: string): Promise<{ items: LoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers`);
  }

  async getLoadBalancer(namespace: string, name: string): Promise<LoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers/${name}`);
  }

  async createHttpLoadBalancer(namespace: string, body: unknown): Promise<LoadBalancer> {
    return this.post(`/api/config/namespaces/${namespace}/http_loadbalancers`, body);
  }

  // --- WAF Policy APIs ---
  async getWAFPolicies(namespace: string): Promise<{ items: WAFPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_firewalls`);
  }

  async createAppFirewall(namespace: string, body: unknown): Promise<any> {
    return this.post(`/api/config/namespaces/${namespace}/app_firewalls`, body);
  }

  // --- Origin Pool APIs ---
  async getOriginPools(namespace: string): Promise<{ items: OriginPool[] }> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools`);
  }

  async getOriginPool(namespace: string, name: string): Promise<OriginPool> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools/${name}`);
  }

  async createOriginPool(namespace: string, body: unknown): Promise<OriginPool> {
    return this.post(`/api/config/namespaces/${namespace}/origin_pools`, body);
  }

  // --- App Types APIs ---
  async getAppTypes(namespace: string): Promise<{ items: AppType[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_types`);
  }

  // --- App Settings APIs ---
  async getAppSettings(namespace: string): Promise<{ items: AppSetting[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings`);
  }

  // --- Virtual Site APIs ---
  async getVirtualSites(namespace: string): Promise<{ items: VirtualSite[] }> {
    return this.get(`/api/config/namespaces/${namespace}/virtual_sites`);
  }

  // --- User Identification APIs ---
  async getUserIdentificationPolicies(namespace: string): Promise<{ items: UserIdentificationPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/user_identification_policys`);
  }

  // --- CDN APIs ---
  async getCDNLoadBalancers(namespace: string): Promise<{ items: CDNLoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_loadbalancers`);
  }

  async getCDNCacheRule(namespace: string, name: string): Promise<CDNCacheRule> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_cache_rules/${name}`);
  }

  // --- Alert Receiver APIs ---
  async getAlertReceivers(namespace: string): Promise<{ items: AlertReceiver[] }> {
    return this.get(`/api/config/namespaces/${namespace}/alert_receivers`);
  }

  async getAlertReceiver(namespace: string, name: string): Promise<AlertReceiver> {
    return this.get(`/api/config/namespaces/${namespace}/alert_receivers/${name}`);
  }

  async createAlertReceiver(namespace: string, body: unknown): Promise<AlertReceiver> {
    return this.post(`/api/config/namespaces/${namespace}/alert_receivers`, body);
  }

  // --- Alert Policy APIs ---
  async getAlertPolicies(namespace: string): Promise<{ items: AlertPolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/alert_policys`);
  }

  async getAlertPolicy(namespace: string, name: string): Promise<AlertPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/alert_policys/${name}`);
  }

  async createAlertPolicy(namespace: string, body: unknown): Promise<AlertPolicy> {
    return this.post(`/api/config/namespaces/${namespace}/alert_policys`, body);
  }

  // --- Service Policy APIs ---
  async getServicePolicies(namespace: string): Promise<{ items: ServicePolicy[] }> {
    return this.get(`/api/config/namespaces/${namespace}/service_policys`);
  }

  async getServicePolicy(namespace: string, name: string): Promise<ServicePolicy> {
    return this.get(`/api/config/namespaces/${namespace}/service_policys/${name}`);
  }

  async updateServicePolicy(namespace: string, name: string, body: unknown): Promise<ServicePolicy> {
    return this.put(`/api/config/namespaces/${namespace}/service_policys/${name}`, body);
  }

  async createServicePolicy(namespace: string, body: unknown): Promise<ServicePolicy> {
    return this.post(`/api/config/namespaces/${namespace}/service_policys`, body);
  }

  // --- IP Prefix Set APIs ---
  async getIpPrefixSets(namespace: string): Promise<{ items: IpPrefixSet[] }> {
    return this.get(`/api/config/namespaces/${namespace}/ip_prefix_sets`);
  }

  async getIpPrefixSet(namespace: string, name: string): Promise<IpPrefixSet> {
    return this.get(`/api/config/namespaces/${namespace}/ip_prefix_sets/${name}`);
  }

  async createIpPrefixSet(namespace: string, body: unknown): Promise<IpPrefixSet> {
    return this.post(`/api/config/namespaces/${namespace}/ip_prefix_sets`, body);
  }

  // --- Certificate APIs ---
  async getCertificates(namespace: string): Promise<{ items: Certificate[] }> {
    return this.get(`/api/config/namespaces/${namespace}/certificates`);
  }
}

export { F5XCApiClient };
export const apiClient = new F5XCApiClient();

const STORAGE_KEY = 'xc_bulkops_credentials';

export const storageManager = {
  saveCredentials(credentials: Credentials) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
  },

  loadCredentials(): Credentials | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  },

  clearCredentials() {
    localStorage.removeItem(STORAGE_KEY);
  },
};