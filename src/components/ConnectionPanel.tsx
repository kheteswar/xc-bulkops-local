import { useState } from 'react';
import { Eye, EyeOff, LogOut, Home, Shield, Check, Loader2 } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';

export function ConnectionPanel() {
  const { isConnected, tenant, isConnecting, connect, disconnect } = useApp();
  const toast = useToast();
  const [tenantInput, setTenantInput] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [remember, setRemember] = useState(true);

  const handleConnect = async () => {
    if (!tenantInput.trim()) {
      toast.warning('Please enter your tenant name');
      return;
    }
    if (!apiToken.trim()) {
      toast.warning('Please enter your API token');
      return;
    }

    try {
      await connect({ tenant: tenantInput.trim(), apiToken: apiToken.trim() }, remember);
      toast.success(`Connected to ${tenantInput.trim()}`);
    } catch {
      toast.error('Connection failed. Please check your credentials.');
    }
  };

  const handleDisconnect = () => {
    disconnect();
    setApiToken('');
    toast.info('Disconnected from F5 XC');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleConnect();
    }
  };

  return (
    <section className="mb-8">
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 relative overflow-hidden">
        <div
          className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-cyan-500 transition-opacity ${
            isConnected ? 'opacity-100' : 'opacity-0'
          }`}
        />

        <div
          className={`flex items-center gap-2 mb-6 px-4 py-2 rounded-full w-fit transition-colors ${
            isConnected
              ? 'bg-emerald-500/15'
              : isConnecting
              ? 'bg-amber-500/15'
              : 'bg-slate-700/50'
          }`}
        >
          <div
            className={`w-2 h-2 rounded-full transition-colors ${
              isConnected
                ? 'bg-emerald-500 shadow-[0_0_8px] shadow-emerald-500 animate-pulse'
                : isConnecting
                ? 'bg-amber-500 animate-pulse'
                : 'bg-slate-500'
            }`}
          />
          <span
            className={`text-xs font-semibold uppercase tracking-wide ${
              isConnected
                ? 'text-emerald-400'
                : isConnecting
                ? 'text-amber-400'
                : 'text-slate-400'
            }`}
          >
            {isConnected ? 'Connected' : isConnecting ? 'Connecting...' : 'Not Connected'}
          </span>
        </div>

        {!isConnected ? (
          <div className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold text-slate-100 mb-2">
                Connect to F5 Distributed Cloud
              </h2>
              <p className="text-slate-400 max-w-xl">
                Enter your tenant name and API token to begin. Your credentials are stored
                locally in your browser and only used to communicate with F5 XC APIs.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-200 mb-2">
                  Tenant Name
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={tenantInput}
                    onChange={e => setTenantInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="your-tenant"
                    className="w-full px-4 py-3 pr-48 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder:text-slate-600"
                  />
                  <span className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 font-mono text-sm pointer-events-none">
                    .console.ves.volterra.io
                  </span>
                </div>
                <span className="text-xs text-slate-500 mt-1 block">
                  Your F5 XC tenant identifier
                </span>
              </div>

              <div>
                <label className="block text-sm font-semibold text-slate-200 mb-2">
                  API Token
                </label>
                <div className="relative">
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={apiToken}
                    onChange={e => setApiToken(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Enter your API token"
                    className="w-full px-4 py-3 pr-12 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 font-mono text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 placeholder:text-slate-600"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    {showToken ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
                <span className="text-xs text-slate-500 mt-1 block">
                  Generate from F5 XC Console - Administration - Credentials
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-6 border-t border-slate-700">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={e => setRemember(e.target.checked)}
                  className="sr-only"
                />
                <div
                  className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
                    remember
                      ? 'bg-blue-500 border-blue-500'
                      : 'border-slate-600 hover:border-slate-500'
                  }`}
                >
                  {remember && <Check className="w-3 h-3 text-white" />}
                </div>
                <span className="text-sm text-slate-400">
                  Remember credentials in this browser
                </span>
              </label>

              <button
                onClick={handleConnect}
                disabled={isConnecting}
                className="px-6 py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-70 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors flex items-center gap-2 shadow-lg shadow-blue-500/20 hover:shadow-blue-500/30"
              >
                {isConnecting ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <span>Connect</span>
                )}
              </button>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-between py-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center text-white shadow-lg shadow-blue-500/30">
                <Home className="w-7 h-7" />
              </div>
              <div>
                <span className="text-xl font-semibold text-slate-100 block">{tenant}</span>
                <span className="text-sm text-slate-500 font-mono">
                  {tenant}.console.ves.volterra.io
                </span>
              </div>
            </div>

            <button
              onClick={handleDisconnect}
              className="flex items-center gap-2 px-6 py-2.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 hover:border-red-500/50 text-red-400 font-medium rounded-lg transition-colors"
            >
              <LogOut className="w-5 h-5" />
              Disconnect
            </button>
          </div>
        )}
      </div>

      <div className="flex items-start gap-3 mt-4 px-4 py-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
        <Shield className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
        <div className="flex flex-col gap-0.5">
          <span className="text-emerald-400 text-sm font-semibold">Secure API Access</span>
          <span className="text-slate-400 text-xs">
            Your API token is only stored locally and sent directly to F5 XC APIs over HTTPS.
          </span>
        </div>
      </div>
    </section>
  );
}
