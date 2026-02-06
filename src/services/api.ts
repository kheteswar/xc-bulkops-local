import type { Credentials, Namespace, LoadBalancer, WAFPolicy, OriginPool, AppType, AppSetting, VirtualSite, UserIdentificationPolicy, AlertReceiver, AlertPolicy, CDNLoadBalancer, CDNCacheRule } from '../types';

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

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || data.message || `API Error: ${response.status}`);
    }

    return data as T;
  }

  // Static method for cross-tenant requests (doesn't use instance tenant/token)
  static async proxyRequestStatic<T>(
    tenant: string,
    apiToken: string,
    endpoint: string,
    method = 'GET',
    body?: unknown
  ): Promise<T> {
    const response = await fetch(PROXY_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant,
        token: apiToken,
        endpoint,
        method,
        body,
      }),
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || data.message || `API Error: ${response.status}`);
    }

    return data as T;
  }

  async get<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'GET');
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.proxyRequest<T>(path, 'POST', body);
  }

  async getNamespaces(): Promise<{ items: Namespace[] }> {
    return this.get('/api/web/namespaces');
  }

  async getLoadBalancers(namespace: string): Promise<{ items: LoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers`);
  }

  async getLoadBalancer(namespace: string, name: string): Promise<LoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers/${name}`);
  }

  async getWAFPolicy(namespace: string, name: string): Promise<WAFPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/app_firewalls/${name}`);
  }

  async getOriginPool(namespace: string, name: string): Promise<OriginPool> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools/${name}`);
  }

  async getHealthCheck(namespace: string, name: string): Promise<unknown> {
    return this.get(`/api/config/namespaces/${namespace}/healthchecks/${name}`);
  }

  async getAppTypes(): Promise<{ items: AppType[] }> {
    return this.get('/api/config/namespaces/shared/app_types');
  }

  async getAppType(name: string): Promise<AppType> {
    return this.get(`/api/config/namespaces/shared/app_types/${name}`);
  }

  async getAppSettings(namespace: string): Promise<{ items: AppSetting[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings`);
  }

  async getAppSetting(namespace: string, name: string): Promise<AppSetting> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings/${name}`);
  }

  async getVirtualSite(namespace: string, name: string): Promise<VirtualSite> {
    return this.get(`/api/config/namespaces/${namespace}/virtual_sites/${name}`);
  }

  async getUserIdentificationPolicy(namespace: string, name: string): Promise<UserIdentificationPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/user_identifications/${name}`);
  }

  async getServicePolicy(namespace: string, policyName: string): Promise<unknown> {
  const primaryPath =
    `/api/config/namespaces/${namespace}/service_policys/${policyName}`;

  try {
    return await this.get(primaryPath);
  } catch (err: any) {
    const isSharedNamespace = namespace === 'shared';
    const isAllowAllPolicy = policyName === 'ves-io-allow-all';

    const msg = err?.message ? String(err.message) : '';
    const looksLike404 =
      msg.includes('404') ||
      msg.toLowerCase().includes('does not exist') ||
      msg.toLowerCase().includes('not exist');

    if (isSharedNamespace && isAllowAllPolicy && looksLike404) {
      return this.get(
        `/api/config/namespaces/ves-io-shared/service_policys/${policyName}`
      );
    }

    throw err;
  }
}
  // --- CDN APIs ---
  async getCDNs(namespace: string): Promise<{ items: CDNLoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_loadbalancers`);
  }

  async getCDN(namespace: string, name: string): Promise<CDNLoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/cdn_loadbalancers/${name}`);
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
