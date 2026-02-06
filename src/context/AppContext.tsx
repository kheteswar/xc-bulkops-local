import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { apiClient, storageManager } from '../services/api';
import type { Credentials } from '../types';

interface AppContextType {
  isConnected: boolean;
  tenant: string | null;
  isConnecting: boolean;
  connect: (credentials: Credentials, remember: boolean) => Promise<void>;
  disconnect: () => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [isConnected, setIsConnected] = useState(false);
  const [tenant, setTenant] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);

  const connect = useCallback(async (credentials: Credentials, remember: boolean) => {
    setIsConnecting(true);
    try {
      apiClient.init(credentials.tenant, credentials.apiToken);
      await apiClient.getNamespaces();

      setIsConnected(true);
      setTenant(credentials.tenant);

      if (remember) {
        storageManager.saveCredentials(credentials);
      }
    } catch (error) {
      apiClient.clear();
      setIsConnected(false);
      setTenant(null);
      throw error;
    } finally {
      setIsConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    apiClient.clear();
    storageManager.clearCredentials();
    setIsConnected(false);
    setTenant(null);
  }, []);

  useEffect(() => {
    const savedCredentials = storageManager.loadCredentials();
    if (savedCredentials) {
      connect(savedCredentials, true).catch(() => {
        storageManager.clearCredentials();
      });
    }
  }, [connect]);

  return (
    <AppContext.Provider value={{ isConnected, tenant, isConnecting, connect, disconnect }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
}
