import React, { useState, useEffect, useCallback } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Check,
  Search,
  Plus,
  X,
  Loader2,
  Server,
  Globe,
  Shield,
  Settings,
  ClipboardList,
  Bot,
  Eye,
  Radar,
  Activity,
  Cpu,
} from 'lucide-react';
import { apiClient } from '../../services/api';
import { useApp } from '../../context/AppContext';
import type { SOCRoomConfig, SOCFeatureFlags, WatchPath } from '../../services/live-soc/types';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface RoomCreatorProps {
  onSave: (room: SOCRoomConfig) => void;
  onCancel: () => void;
  editRoom?: SOCRoomConfig | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STEPS = ['Basics', 'Objects', 'Features', 'Polling', 'Confirm'] as const;

const GLASS =
  'bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl';

const POLLING_INTERVALS: { label: string; value: 120 | 180 | 300 }[] = [
  { label: '2 min', value: 120 },
  { label: '3 min', value: 180 },
  { label: '5 min', value: 300 },
];

const DATA_WINDOWS: { label: string; value: 5 | 10 | 15 }[] = [
  { label: '5 min', value: 5 },
  { label: '10 min', value: 10 },
  { label: '15 min', value: 15 },
];

const FETCH_DEPTHS: { label: string; value: 'light' | 'standard' | 'deep'; desc: string }[] = [
  { label: 'Light', value: 'light', desc: 'Aggregations only' },
  { label: 'Standard', value: 'standard', desc: '+ raw log sampling' },
  { label: 'Deep', value: 'deep', desc: '+ bot, CSD, DNS, API' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ---------------------------------------------------------------------------
// Sub-component: Searchable Multi-Select
// ---------------------------------------------------------------------------

interface MultiSelectProps {
  label: string;
  icon: React.ReactNode;
  items: string[];
  selected: string[];
  onChange: (selected: string[]) => void;
  loading?: boolean;
  placeholder?: string;
}

function MultiSelect({ label, icon, items, selected, onChange, loading, placeholder }: MultiSelectProps) {
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState(false);

  const filtered = items.filter((i) =>
    i.toLowerCase().includes(search.toLowerCase()),
  );

  const toggleItem = (item: string) => {
    onChange(
      selected.includes(item)
        ? selected.filter((s) => s !== item)
        : [...selected, item],
    );
  };

  const selectAll = () => onChange([...items]);
  const deselectAll = () => onChange([]);

  return (
    <div className="mb-4">
      <label className="flex items-center gap-2 text-sm font-medium text-gray-300 mb-1.5">
        {icon}
        {label}
        <span className="text-[#00d4ff]/60 text-xs ml-auto">
          {selected.length}/{items.length} selected
        </span>
      </label>

      <div className={`${GLASS} overflow-hidden`}>
        {/* Search bar */}
        <div className="flex items-center gap-2 px-3 py-2 border-b border-[#1a2332]">
          <Search size={14} className="text-gray-500" />
          <input
            type="text"
            className="bg-transparent text-sm text-gray-200 outline-none flex-1 placeholder-gray-600"
            placeholder={placeholder || `Search ${label.toLowerCase()}...`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onFocus={() => setOpen(true)}
          />
          <button
            type="button"
            className="text-xs text-[#00d4ff] hover:text-[#00d4ff]/80"
            onClick={selectAll}
          >
            All
          </button>
          <button
            type="button"
            className="text-xs text-gray-500 hover:text-gray-300"
            onClick={deselectAll}
          >
            None
          </button>
        </div>

        {/* Item list */}
        {loading ? (
          <div className="flex items-center justify-center py-6 text-gray-500">
            <Loader2 size={16} className="animate-spin mr-2" />
            Loading...
          </div>
        ) : (
          <div className={`max-h-48 overflow-y-auto transition-all ${open ? 'max-h-48' : 'max-h-0'}`}>
            {filtered.length === 0 ? (
              <div className="px-3 py-4 text-sm text-gray-600 text-center">
                {items.length === 0 ? 'No items available' : 'No matches'}
              </div>
            ) : (
              filtered.map((item) => (
                <button
                  key={item}
                  type="button"
                  className="w-full flex items-center gap-2 px-3 py-1.5 text-sm hover:bg-[#1a2332]/60 transition-colors text-left"
                  onClick={() => toggleItem(item)}
                >
                  <div
                    className={`w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors ${
                      selected.includes(item)
                        ? 'bg-[#00d4ff] border-[#00d4ff]'
                        : 'border-gray-600'
                    }`}
                  >
                    {selected.includes(item) && (
                      <Check size={10} className="text-[#0a0e1a]" />
                    )}
                  </div>
                  <span className="text-gray-300 truncate">{item}</span>
                </button>
              ))
            )}
          </div>
        )}

        {/* Selected tags */}
        {selected.length > 0 && (
          <div className="flex flex-wrap gap-1.5 px-3 py-2 border-t border-[#1a2332]">
            {selected.slice(0, 5).map((item) => (
              <span
                key={item}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20"
              >
                {item}
                <X
                  size={10}
                  className="cursor-pointer hover:text-white"
                  onClick={() => toggleItem(item)}
                />
              </span>
            ))}
            {selected.length > 5 && (
              <span className="text-xs text-gray-500 self-center">
                +{selected.length - 5} more
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function RoomCreator({ onSave, onCancel, editRoom }: RoomCreatorProps) {
  const { isConnected } = useApp();
  const isEditing = Boolean(editRoom);

  // Step navigation
  const [step, setStep] = useState(0);

  // Step 1: Basics
  const [roomName, setRoomName] = useState(editRoom?.name ?? '');
  const [namespace, setNamespace] = useState(editRoom?.namespace ?? '');
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [nsLoading, setNsLoading] = useState(false);

  // Step 2: Monitored Objects
  const [lbNames, setLbNames] = useState<string[]>([]);
  const [cdnNames, setCdnNames] = useState<string[]>([]);
  const [lbsLoading, setLbsLoading] = useState(false);
  const [cdnsLoading, setCdnsLoading] = useState(false);
  const [selectedLbs, setSelectedLbs] = useState<string[]>(editRoom?.loadBalancers ?? []);
  const [selectedCdns, setSelectedCdns] = useState<string[]>(editRoom?.cdnDistributions ?? []);
  const [selectedDnsZones, setSelectedDnsZones] = useState<string[]>(editRoom?.dnsZones ?? []);
  const [selectedDnsLbs, setSelectedDnsLbs] = useState<string[]>(editRoom?.dnsLoadBalancers ?? []);
  const [dnsZoneNames, setDnsZoneNames] = useState<string[]>([]);
  const [dnsLbNames, setDnsLbNames] = useState<string[]>([]);
  const [dnsZonesLoading, setDnsZonesLoading] = useState(false);
  const [dnsLbsLoading, setDnsLbsLoading] = useState(false);

  // Step 3: Features
  const [features, setFeatures] = useState<SOCFeatureFlags>(
    editRoom?.features ?? {
      botDefenseEnabled: false,
      clientSideDefenseEnabled: false,
      infraProtectEnabled: false,
      syntheticMonitorsEnabled: false,
      apiSecurityEnabled: false,
    },
  );
  const [detecting, setDetecting] = useState(false);
  const [detected, setDetected] = useState(false);

  // Step 4: Polling
  const [pollingInterval, setPollingInterval] = useState<120 | 180 | 300>(
    editRoom?.pollingIntervalSec ?? 180,
  );
  const [dataWindow, setDataWindow] = useState<5 | 10 | 15>(
    editRoom?.dataWindowMinutes ?? 10,
  );
  const [fetchDepth, setFetchDepth] = useState<'light' | 'standard' | 'deep'>(
    editRoom?.fetchDepth ?? 'standard',
  );
  const [watchPaths, setWatchPaths] = useState<WatchPath[]>(
    editRoom?.watchPaths ?? [],
  );
  const [newPath, setNewPath] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [newErrThreshold, setNewErrThreshold] = useState('');
  const [newLatThreshold, setNewLatThreshold] = useState('');

  // ---- Fetch namespaces on mount ----
  useEffect(() => {
    if (!isConnected) return;
    setNsLoading(true);
    apiClient
      .getNamespaces()
      .then((res) => {
        const names = (res.items || []).map((n: { name: string }) => n.name).sort();
        setNamespaces(names);
      })
      .catch(() => setNamespaces([]))
      .finally(() => setNsLoading(false));
  }, [isConnected]);

  // ---- Fetch objects when namespace changes ----
  useEffect(() => {
    if (!namespace) return;

    // HTTP Load Balancers
    setLbsLoading(true);
    apiClient
      .getLoadBalancers(namespace)
      .then((res) => setLbNames((res.items || []).map((lb: { name: string }) => lb.name).sort()))
      .catch(() => setLbNames([]))
      .finally(() => setLbsLoading(false));

    // CDN Distributions
    setCdnsLoading(true);
    apiClient
      .getCDNLoadBalancers(namespace)
      .then((res) => setCdnNames((res.items || []).map((c: { name: string }) => c.name).sort()))
      .catch(() => setCdnNames([]))
      .finally(() => setCdnsLoading(false));

    // DNS Zones
    setDnsZonesLoading(true);
    apiClient
      .get<{ items?: { name: string }[] }>(`/api/config/namespaces/${namespace}/dns_zones`)
      .then((res) => setDnsZoneNames((res.items || []).map((z) => z.name).sort()))
      .catch(() => setDnsZoneNames([]))
      .finally(() => setDnsZonesLoading(false));

    // DNS Load Balancers
    setDnsLbsLoading(true);
    apiClient
      .get<{ items?: { name: string }[] }>(`/api/config/namespaces/${namespace}/dns_loadbalancers`)
      .then((res) => setDnsLbNames((res.items || []).map((d) => d.name).sort()))
      .catch(() => setDnsLbNames([]))
      .finally(() => setDnsLbsLoading(false));
  }, [namespace]);

  // ---- Auto-detect features from first LB ----
  const detectFeatures = useCallback(async () => {
    if (selectedLbs.length === 0 || !namespace) return;
    setDetecting(true);
    try {
      const lb = await apiClient.getLoadBalancer(namespace, selectedLbs[0]);
      const spec = lb.spec || ({} as Record<string, unknown>);

      setFeatures((prev) => ({
        ...prev,
        botDefenseEnabled: Boolean(spec.bot_defense && !spec.disable_bot_defense),
        clientSideDefenseEnabled: Boolean(spec.client_side_defense && !spec.disable_client_side_defense),
        apiSecurityEnabled: Boolean(
          spec.enable_api_discovery || spec.api_definition || (spec.api_definition && !spec.disable_api_definition),
        ),
      }));
      setDetected(true);
    } catch {
      // Silently ignore detection errors; user can toggle manually
    } finally {
      setDetecting(false);
    }
  }, [selectedLbs, namespace]);

  useEffect(() => {
    if (step === 2 && selectedLbs.length > 0 && !detected) {
      detectFeatures();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // ---- Watch path management ----
  const addWatchPath = () => {
    const path = newPath.trim();
    const label = newLabel.trim() || path;
    if (!path) return;
    setWatchPaths((prev) => [
      ...prev,
      {
        path,
        label,
        errorThreshold: newErrThreshold ? Number(newErrThreshold) : undefined,
        latencyThresholdMs: newLatThreshold ? Number(newLatThreshold) : undefined,
      },
    ]);
    setNewPath('');
    setNewLabel('');
    setNewErrThreshold('');
    setNewLatThreshold('');
  };

  const removeWatchPath = (idx: number) =>
    setWatchPaths((prev) => prev.filter((_, i) => i !== idx));

  // ---- Build & save ----
  const handleSave = () => {
    const now = new Date().toISOString();
    const room: SOCRoomConfig = {
      id: editRoom?.id ?? generateId(),
      name: roomName.trim(),
      namespace,
      loadBalancers: selectedLbs,
      cdnDistributions: selectedCdns,
      dnsZones: selectedDnsZones,
      dnsLoadBalancers: selectedDnsLbs,
      features,
      pollingIntervalSec: pollingInterval,
      dataWindowMinutes: dataWindow,
      fetchDepth,
      watchPaths,
      createdAt: editRoom?.createdAt ?? now,
      lastOpenedAt: now,
    };
    onSave(room);
  };

  // ---- Validation per step ----
  const canAdvance = (): boolean => {
    switch (step) {
      case 0:
        return roomName.trim().length > 0 && namespace.length > 0;
      case 1:
        return selectedLbs.length > 0;
      default:
        return true;
    }
  };

  // ---------------------------------------------------------------------------
  // Renderers
  // ---------------------------------------------------------------------------

  const renderStepIndicator = () => (
    <div className="flex items-center justify-center gap-2 mb-6">
      {STEPS.map((s, i) => (
        <button
          key={s}
          type="button"
          onClick={() => i < step && setStep(i)}
          className={`flex items-center gap-1.5 text-xs font-medium transition-colors ${
            i === step
              ? 'text-[#00d4ff]'
              : i < step
              ? 'text-[#00ff88] cursor-pointer hover:text-[#00ff88]/80'
              : 'text-gray-600'
          }`}
        >
          <div
            className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border transition-colors ${
              i === step
                ? 'border-[#00d4ff] bg-[#00d4ff]/10 text-[#00d4ff]'
                : i < step
                ? 'border-[#00ff88] bg-[#00ff88]/10 text-[#00ff88]'
                : 'border-gray-700 text-gray-600'
            }`}
          >
            {i < step ? <Check size={12} /> : i + 1}
          </div>
          <span className="hidden sm:inline">{s}</span>
          {i < STEPS.length - 1 && (
            <div
              className={`w-6 h-px ${
                i < step ? 'bg-[#00ff88]/40' : 'bg-gray-700'
              }`}
            />
          )}
        </button>
      ))}
    </div>
  );

  // ---- Step 1: Basics ----
  const renderBasics = () => (
    <div className="space-y-5">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          Room Name
        </label>
        <input
          type="text"
          className={`w-full px-3 py-2.5 rounded-lg bg-[#0a0e1a] border border-[#1a2332] text-gray-100 text-sm outline-none focus:border-[#00d4ff]/50 transition-colors`}
          placeholder="e.g., Production SOC – qatarenergy"
          value={roomName}
          onChange={(e) => setRoomName(e.target.value)}
          autoFocus
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          Namespace
        </label>
        {nsLoading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <Loader2 size={14} className="animate-spin" />
            Loading namespaces...
          </div>
        ) : (
          <select
            className="w-full px-3 py-2.5 rounded-lg bg-[#0a0e1a] border border-[#1a2332] text-gray-100 text-sm outline-none focus:border-[#00d4ff]/50 transition-colors"
            value={namespace}
            onChange={(e) => {
              setNamespace(e.target.value);
              setSelectedLbs([]);
              setSelectedCdns([]);
              setSelectedDnsZones([]);
              setSelectedDnsLbs([]);
              setDetected(false);
            }}
          >
            <option value="">Select namespace...</option>
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>
                {ns}
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  );

  // ---- Step 2: Monitored Objects ----
  const renderObjects = () => (
    <div className="space-y-2">
      <MultiSelect
        label="HTTP Load Balancers"
        icon={<Server size={14} className="text-[#00d4ff]" />}
        items={lbNames}
        selected={selectedLbs}
        onChange={setSelectedLbs}
        loading={lbsLoading}
        placeholder="Search load balancers..."
      />
      <MultiSelect
        label="CDN Distributions"
        icon={<Globe size={14} className="text-[#00ff88]" />}
        items={cdnNames}
        selected={selectedCdns}
        onChange={setSelectedCdns}
        loading={cdnsLoading}
        placeholder="Search CDN distributions..."
      />
      <MultiSelect
        label="DNS Zones"
        icon={<Globe size={14} className="text-[#ffbe0b]" />}
        items={dnsZoneNames}
        selected={selectedDnsZones}
        onChange={setSelectedDnsZones}
        loading={dnsZonesLoading}
        placeholder="Search DNS zones..."
      />
      <MultiSelect
        label="DNS Load Balancers"
        icon={<Activity size={14} className="text-[#ff6b35]" />}
        items={dnsLbNames}
        selected={selectedDnsLbs}
        onChange={setSelectedDnsLbs}
        loading={dnsLbsLoading}
        placeholder="Search DNS load balancers..."
      />
    </div>
  );

  // ---- Step 3: Feature Detection ----
  const renderFeatures = () => {
    const toggles: {
      key: keyof SOCFeatureFlags;
      label: string;
      icon: React.ReactNode;
      autoDetectable: boolean;
    }[] = [
      { key: 'botDefenseEnabled', label: 'Bot Defense', icon: <Bot size={14} />, autoDetectable: true },
      { key: 'clientSideDefenseEnabled', label: 'Client-Side Defense', icon: <Eye size={14} />, autoDetectable: true },
      { key: 'apiSecurityEnabled', label: 'API Security', icon: <Shield size={14} />, autoDetectable: true },
      { key: 'infraProtectEnabled', label: 'InfraProtect (L3/L4)', icon: <Radar size={14} />, autoDetectable: false },
      { key: 'syntheticMonitorsEnabled', label: 'Synthetic Monitors', icon: <Activity size={14} />, autoDetectable: false },
    ];

    return (
      <div className="space-y-4">
        {detecting && (
          <div className="flex items-center gap-2 text-sm text-[#00d4ff]">
            <Loader2 size={14} className="animate-spin" />
            Detecting features from {selectedLbs[0]}...
          </div>
        )}

        {!detecting && detected && (
          <div className="text-xs text-[#00ff88]/70 mb-2">
            Auto-detected from <span className="font-mono text-[#00ff88]">{selectedLbs[0]}</span>. Override with toggles below.
          </div>
        )}

        <div className={`${GLASS} p-4 space-y-3`}>
          {toggles.map(({ key, label, icon, autoDetectable }) => (
            <div
              key={key}
              className="flex items-center justify-between py-1.5"
            >
              <div className="flex items-center gap-2 text-sm text-gray-300">
                <span className={features[key] ? 'text-[#00ff88]' : 'text-gray-600'}>{icon}</span>
                {label}
                {!autoDetectable && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ffbe0b]/10 text-[#ffbe0b] border border-[#ffbe0b]/20">
                    manual
                  </span>
                )}
              </div>
              <button
                type="button"
                className={`relative w-10 h-5 rounded-full transition-colors ${
                  features[key] ? 'bg-[#00ff88]/30' : 'bg-gray-700'
                }`}
                onClick={() =>
                  setFeatures((prev) => ({ ...prev, [key]: !prev[key] }))
                }
              >
                <div
                  className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${
                    features[key]
                      ? 'left-5 bg-[#00ff88]'
                      : 'left-0.5 bg-gray-500'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>

        {!detecting && (
          <button
            type="button"
            className="text-xs text-[#00d4ff] hover:text-[#00d4ff]/80 flex items-center gap-1"
            onClick={() => { setDetected(false); detectFeatures(); }}
          >
            <Cpu size={12} /> Re-detect from LB config
          </button>
        )}
      </div>
    );
  };

  // ---- Step 4: Polling Config ----
  const renderPolling = () => (
    <div className="space-y-5">
      {/* Polling Interval */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Polling Interval
        </label>
        <div className="flex gap-2">
          {POLLING_INTERVALS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors border ${
                pollingInterval === opt.value
                  ? 'border-[#00d4ff] bg-[#00d4ff]/10 text-[#00d4ff]'
                  : 'border-[#1a2332] text-gray-500 hover:text-gray-300'
              }`}
              onClick={() => setPollingInterval(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Data Window */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Data Window
        </label>
        <div className="flex gap-2">
          {DATA_WINDOWS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors border ${
                dataWindow === opt.value
                  ? 'border-[#00d4ff] bg-[#00d4ff]/10 text-[#00d4ff]'
                  : 'border-[#1a2332] text-gray-500 hover:text-gray-300'
              }`}
              onClick={() => setDataWindow(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Fetch Depth */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Fetch Depth
        </label>
        <div className="flex gap-2">
          {FETCH_DEPTHS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors border text-left ${
                fetchDepth === opt.value
                  ? 'border-[#00d4ff] bg-[#00d4ff]/10 text-[#00d4ff]'
                  : 'border-[#1a2332] text-gray-500 hover:text-gray-300'
              }`}
              onClick={() => setFetchDepth(opt.value)}
            >
              <div>{opt.label}</div>
              <div className="text-[10px] opacity-60 mt-0.5">{opt.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Watch Paths */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Watch Paths
        </label>
        <div className={`${GLASS} p-3 space-y-2`}>
          {watchPaths.map((wp, idx) => (
            <div
              key={idx}
              className="flex items-center gap-2 text-sm text-gray-300"
            >
              <span className="font-mono text-[#00d4ff] text-xs flex-1 truncate">
                {wp.path}
              </span>
              <span className="text-gray-500 text-xs truncate max-w-[100px]">
                {wp.label}
              </span>
              {wp.errorThreshold != null && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ff0040]/10 text-[#ff0040]">
                  err&gt;{wp.errorThreshold}%
                </span>
              )}
              {wp.latencyThresholdMs != null && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#ffbe0b]/10 text-[#ffbe0b]">
                  lat&gt;{wp.latencyThresholdMs}ms
                </span>
              )}
              <button
                type="button"
                onClick={() => removeWatchPath(idx)}
                className="text-gray-600 hover:text-[#ff0040] transition-colors"
              >
                <X size={14} />
              </button>
            </div>
          ))}

          {/* Add row */}
          <div className="flex items-end gap-2 pt-2 border-t border-[#1a2332]">
            <div className="flex-1 min-w-0">
              <span className="text-[10px] text-gray-500">Path</span>
              <input
                type="text"
                className="w-full px-2 py-1.5 rounded bg-[#0a0e1a] border border-[#1a2332] text-xs text-gray-200 outline-none"
                placeholder="/api/v1/orders"
                value={newPath}
                onChange={(e) => setNewPath(e.target.value)}
              />
            </div>
            <div className="w-24">
              <span className="text-[10px] text-gray-500">Label</span>
              <input
                type="text"
                className="w-full px-2 py-1.5 rounded bg-[#0a0e1a] border border-[#1a2332] text-xs text-gray-200 outline-none"
                placeholder="Orders"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
              />
            </div>
            <div className="w-16">
              <span className="text-[10px] text-gray-500">Err %</span>
              <input
                type="number"
                className="w-full px-2 py-1.5 rounded bg-[#0a0e1a] border border-[#1a2332] text-xs text-gray-200 outline-none"
                placeholder="5"
                value={newErrThreshold}
                onChange={(e) => setNewErrThreshold(e.target.value)}
              />
            </div>
            <div className="w-16">
              <span className="text-[10px] text-gray-500">Lat ms</span>
              <input
                type="number"
                className="w-full px-2 py-1.5 rounded bg-[#0a0e1a] border border-[#1a2332] text-xs text-gray-200 outline-none"
                placeholder="500"
                value={newLatThreshold}
                onChange={(e) => setNewLatThreshold(e.target.value)}
              />
            </div>
            <button
              type="button"
              onClick={addWatchPath}
              disabled={!newPath.trim()}
              className="px-2 py-1.5 rounded bg-[#00d4ff]/10 text-[#00d4ff] hover:bg-[#00d4ff]/20 disabled:opacity-30 transition-colors"
            >
              <Plus size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  // ---- Step 5: Confirm ----
  const renderConfirm = () => {
    const enabledFeatures = Object.entries(features)
      .filter(([, v]) => v)
      .map(([k]) =>
        k
          .replace('Enabled', '')
          .replace(/([A-Z])/g, ' $1')
          .trim(),
      );

    return (
      <div className="space-y-4">
        <div className={`${GLASS} p-4 space-y-3 text-sm`}>
          <div className="flex justify-between">
            <span className="text-gray-500">Room Name</span>
            <span className="text-gray-200 font-medium">{roomName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Namespace</span>
            <span className="font-mono text-[#00d4ff] text-xs">{namespace}</span>
          </div>
          <div className="border-t border-[#1a2332] pt-3 flex justify-between">
            <span className="text-gray-500">HTTP LBs</span>
            <span className="text-gray-200">{selectedLbs.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">CDN Distributions</span>
            <span className="text-gray-200">{selectedCdns.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">DNS Zones</span>
            <span className="text-gray-200">{selectedDnsZones.length}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">DNS LBs</span>
            <span className="text-gray-200">{selectedDnsLbs.length}</span>
          </div>
          <div className="border-t border-[#1a2332] pt-3 flex justify-between">
            <span className="text-gray-500">Features</span>
            <span className="text-[#00ff88] text-xs text-right max-w-[200px]">
              {enabledFeatures.length > 0 ? enabledFeatures.join(', ') : 'None'}
            </span>
          </div>
          <div className="border-t border-[#1a2332] pt-3 flex justify-between">
            <span className="text-gray-500">Polling</span>
            <span className="text-gray-200 text-xs">
              Every {pollingInterval / 60}m &middot; {dataWindow}m window &middot;{' '}
              {fetchDepth}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Watch Paths</span>
            <span className="text-gray-200">{watchPaths.length}</span>
          </div>
        </div>

        {/* Object lists */}
        {selectedLbs.length > 0 && (
          <div className={`${GLASS} p-3`}>
            <div className="text-xs font-medium text-gray-500 mb-1.5 flex items-center gap-1">
              <Server size={12} /> Load Balancers
            </div>
            <div className="flex flex-wrap gap-1.5">
              {selectedLbs.map((lb) => (
                <span
                  key={lb}
                  className="px-2 py-0.5 text-[11px] rounded-full bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/20"
                >
                  {lb}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  // ---------------------------------------------------------------------------
  // Main render
  // ---------------------------------------------------------------------------

  const stepRenderers = [renderBasics, renderObjects, renderFeatures, renderPolling, renderConfirm];

  return (
    <div className={`${GLASS} p-6 max-w-2xl mx-auto`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
          <Settings size={18} className="text-[#00d4ff]" />
          {isEditing ? 'Edit SOC Room' : 'Create SOC Room'}
        </h2>
        <button
          type="button"
          onClick={onCancel}
          className="text-gray-500 hover:text-gray-300 transition-colors"
        >
          <X size={18} />
        </button>
      </div>

      {/* Step indicator */}
      {renderStepIndicator()}

      {/* Step content */}
      <div className="min-h-[300px]">
        {stepRenderers[step]()}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between mt-6 pt-4 border-t border-[#1a2332]">
        <button
          type="button"
          onClick={() => (step === 0 ? onCancel() : setStep(step - 1))}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm text-gray-400 hover:text-gray-200 transition-colors"
        >
          <ChevronLeft size={16} />
          {step === 0 ? 'Cancel' : 'Back'}
        </button>

        {step < STEPS.length - 1 ? (
          <button
            type="button"
            disabled={!canAdvance()}
            onClick={() => setStep(step + 1)}
            className="flex items-center gap-1.5 px-5 py-2 rounded-lg text-sm font-medium bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30 hover:bg-[#00d4ff]/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next
            <ChevronRight size={16} />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSave}
            className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg text-sm font-semibold bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/30 hover:bg-[#00ff88]/20 transition-colors"
          >
            <ClipboardList size={16} />
            {isEditing ? 'Save Room' : 'Create Room'}
          </button>
        )}
      </div>
    </div>
  );
}
