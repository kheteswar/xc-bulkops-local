// =============================================================================
// Live SOC Monitoring Room — Main Room Page
// =============================================================================
// Route: /soc-room/:roomId
// Composition root hosting the useReducer state machine, PollingEngine
// lifecycle, post-cycle anomaly detection pipeline, and all dashboard panels.
// =============================================================================

import { useReducer, useEffect, useRef, useCallback, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Pause, Play, Download, RotateCcw } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';

// Service imports
import {
  type SOCRoomConfig, type SOCRoomState, type SOCAction, type ThreatLevel,
  type Incident, type Investigation,
  type TimeSeriesPoint, type CycleSnapshot, type Baseline,
  createEmptyMetrics, createEmptyLatencyStats, createEmptyBaseline, EMPTY_AGGREGATION,
  getRoomById, getBaseline, saveBaseline, setLastRoomId,
  calculateMetrics, evaluateDetectors, updateBaseline, computeThreatLevel,
  reconcileIncidents, createInvestigation, executeInvestigation,
  ERROR_DIAGNOSIS_KB,
  PollingEngine,
} from '../services/live-soc';
import { reconcileAnomalies } from '../services/live-soc/anomaly-detector';
import { DETECTOR_TO_WORKFLOW } from '../services/live-soc/investigation-chains';

// Component imports
import SOCThemeWrapper from '../components/soc/SOCThemeWrapper';
import StatusStrip from '../components/soc/StatusStrip';
import TrafficTimeSeries from '../components/soc/TrafficTimeSeries';
import ResponseCodeDist from '../components/soc/ResponseCodeDist';
import ErrorDiagnosis from '../components/soc/ErrorDiagnosis';
import OriginHealthGrid from '../components/soc/OriginHealthGrid';
import SecurityBreakdown from '../components/soc/SecurityBreakdown';
import LatencyWaterfall from '../components/soc/LatencyWaterfall';
import BotIntelligence from '../components/soc/BotIntelligence';
import CDNMonitor from '../components/soc/CDNMonitor';
import CSDMonitor from '../components/soc/CSDMonitor';
import LiveEventFeed from '../components/soc/LiveEventFeed';
import IncidentTimeline from '../components/soc/IncidentTimeline';

// =============================================================================
// Constants
// =============================================================================

const MAX_TIME_SERIES_POINTS = 288; // ~24h at 5-min intervals
const MAX_SNAPSHOTS = 72;           // ~6h at 5-min intervals
const MAX_EVENT_FEED = 1000;
const GLASS = 'bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4';
const BASELINE_PERSIST_INTERVAL = 5; // Persist baseline every N cycles

// =============================================================================
// Initial State Factory
// =============================================================================

function createInitialState(room: SOCRoomConfig, baseline: Baseline): SOCRoomState {
  return {
    room,
    pollingStatus: 'idle',
    cycleNumber: 0,
    lastCycleTimestamp: null,
    nextCycleIn: room.pollingIntervalSec,
    isCatchingUp: false,

    heartbeat: { totalHits: 0, secEventHits: 0, rps: 0, timestamp: '' },
    aggregation: { ...EMPTY_AGGREGATION },
    alerts: [],
    auditEntries: [],
    suspiciousUserCount: 0,

    botOverview: null,
    syntheticHealth: null,
    dnsHealth: null,
    csdSummary: null,
    infraProtect: null,
    apiSecurity: null,

    latencyStats: createEmptyLatencyStats(),
    eventFeed: [],
    ja4Clusters: [],
    rawLogSampleRate: 1,

    metrics: createEmptyMetrics(),
    baseline,
    activeAnomalies: [],
    threatLevel: 'NOMINAL',

    incidents: [],
    activeInvestigations: [],
    completedInvestigations: [],

    timeSeriesHistory: [],
    snapshotHistory: [],

    selectedDomain: null,
    historyMode: false,
    historyCursor: null,

    error: null,
  };
}

// =============================================================================
// Reducer
// =============================================================================

function socReducer(state: SOCRoomState, action: SOCAction): SOCRoomState {
  switch (action.type) {
    // ── Polling lifecycle ───────────────────────────────────────────
    case 'CYCLE_START':
      return {
        ...state,
        cycleNumber: state.cycleNumber + 1,
        isCatchingUp: false,
        pollingStatus: 'running',
        error: null,
      };

    case 'CYCLE_RESULT': {
      const p = action.payload;
      // Merge new event feed entries (prepend, capped)
      const mergedFeed = [...p.rawLogs.eventFeed, ...state.eventFeed].slice(0, MAX_EVENT_FEED);
      return {
        ...state,
        heartbeat: p.heartbeat,
        aggregation: p.aggregation,
        alerts: p.alerts,
        auditEntries: p.auditEntries,
        suspiciousUserCount: p.suspiciousUserCount,
        latencyStats: p.rawLogs.latencyStats,
        ja4Clusters: p.rawLogs.ja4Clusters,
        rawLogSampleRate: p.rawLogs.sampleRate,
        eventFeed: mergedFeed,
        botOverview: p.botOverview ?? state.botOverview,
        syntheticHealth: p.syntheticHealth ?? state.syntheticHealth,
        dnsHealth: p.dnsHealth ?? state.dnsHealth,
        lastCycleTimestamp: new Date().toISOString(),
      };
    }

    case 'CYCLE_COMPLETE': {
      const { metrics, anomalies, threatLevel, baseline, incidents } = action.payload;

      // Build time series point
      const tsPoint: TimeSeriesPoint = {
        timestamp: new Date().toISOString(),
        rps: metrics.rps,
        errorRate: metrics.errorRate,
        secEvents: metrics.totalSecEvents,
        p95Latency: state.latencyStats.p95,
        threatLevel,
      };

      // Build snapshot for history scrubber
      const snapshot: CycleSnapshot = {
        cycleNumber: state.cycleNumber,
        timestamp: new Date().toISOString(),
        metrics,
        latencyStats: state.latencyStats,
        aggregation: state.aggregation,
        anomalies,
        threatLevel,
        heartbeat: state.heartbeat,
      };

      return {
        ...state,
        metrics,
        activeAnomalies: anomalies,
        threatLevel,
        baseline,
        incidents,
        pollingStatus: 'running',
        nextCycleIn: state.room.pollingIntervalSec,
        timeSeriesHistory: [...state.timeSeriesHistory, tsPoint].slice(-MAX_TIME_SERIES_POINTS),
        snapshotHistory: [...state.snapshotHistory, snapshot].slice(-MAX_SNAPSHOTS),
      };
    }

    // ── Investigation lifecycle ────────────────────────────────────
    case 'INVESTIGATION_UPDATE': {
      const updated = action.payload;
      return {
        ...state,
        activeInvestigations: state.activeInvestigations.map(inv =>
          inv.id === updated.id ? updated : inv
        ),
      };
    }

    case 'INVESTIGATION_COMPLETE': {
      const completed = action.payload;
      return {
        ...state,
        activeInvestigations: state.activeInvestigations.filter(inv => inv.id !== completed.id),
        completedInvestigations: [completed, ...state.completedInvestigations],
      };
    }

    // ── Feature-specific results (fetched outside main cycle) ─────
    case 'CSD_RESULT':
      return { ...state, csdSummary: action.payload };

    case 'INFRAPROTECT_RESULT':
      return { ...state, infraProtect: action.payload };

    case 'API_SECURITY_RESULT':
      return { ...state, apiSecurity: action.payload };

    // ── UI controls ────────────────────────────────────────────────
    case 'SET_DOMAIN_FILTER':
      return { ...state, selectedDomain: action.payload };

    case 'SET_HISTORY_MODE':
      return {
        ...state,
        historyMode: action.payload.enabled,
        historyCursor: action.payload.cursor ?? null,
      };

    case 'APPLY_SNAPSHOT': {
      const snap = action.payload;
      return {
        ...state,
        metrics: snap.metrics,
        aggregation: snap.aggregation,
        latencyStats: snap.latencyStats,
        activeAnomalies: snap.anomalies,
        threatLevel: snap.threatLevel,
        heartbeat: snap.heartbeat,
      };
    }

    // ── Polling controls ───────────────────────────────────────────
    case 'POLLING_PAUSED':
      return { ...state, pollingStatus: 'paused' };

    case 'POLLING_RESUMED':
      return { ...state, pollingStatus: 'running' };

    case 'POLLING_ERROR':
      return {
        ...state,
        pollingStatus: 'error',
        error: action.payload,
      };

    case 'COUNTDOWN_TICK':
      return {
        ...state,
        nextCycleIn: Math.max(0, state.nextCycleIn - 1),
      };

    case 'BASELINE_RESET':
      return {
        ...state,
        baseline: createEmptyBaseline(),
        activeAnomalies: [],
        threatLevel: 'NOMINAL',
      };

    case 'ADD_EVENT': {
      const entry = action.payload;
      return {
        ...state,
        eventFeed: [entry, ...state.eventFeed].slice(0, MAX_EVENT_FEED),
      };
    }

    default:
      return state;
  }
}

// =============================================================================
// Component
// =============================================================================

export function SOCRoom() {
  const { roomId } = useParams<{ roomId: string }>();
  const navigate = useNavigate();
  const { isConnected } = useApp();
  const toast = useToast();

  // ── Load room config ──────────────────────────────────────────────
  const room = roomId ? getRoomById(roomId) : null;
  const savedBaseline = room ? getBaseline(room.id) : null;

  // ── Reducer ───────────────────────────────────────────────────────
  const [state, dispatch] = useReducer(
    socReducer,
    room
      ? createInitialState(room, savedBaseline || createEmptyBaseline())
      : createInitialState(
          // Dummy room to avoid null — gated by early return below
          {
            id: '', name: '', namespace: '', loadBalancers: [],
            cdnDistributions: [], dnsZones: [], dnsLoadBalancers: [],
            features: {
              botDefenseEnabled: false, clientSideDefenseEnabled: false,
              infraProtectEnabled: false, syntheticMonitorsEnabled: false,
              apiSecurityEnabled: false,
            },
            pollingIntervalSec: 180, dataWindowMinutes: 5, fetchDepth: 'standard',
            watchPaths: [], createdAt: '', lastOpenedAt: '',
          },
          createEmptyBaseline(),
        ),
  );

  const engineRef = useRef<PollingEngine | null>(null);
  const cycleProcessedRef = useRef(0); // Track which cycle we last processed

  // ── Mark last-opened room ─────────────────────────────────────────
  useEffect(() => {
    if (roomId) setLastRoomId(roomId);
  }, [roomId]);

  // ── Initialize polling engine ─────────────────────────────────────
  useEffect(() => {
    if (!room || !isConnected) return;

    const engine = new PollingEngine(room, dispatch);
    engineRef.current = engine;
    engine.start();

    dispatch({
      type: 'ADD_EVENT',
      payload: {
        id: `sys-${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: 'config',
        severity: 'info',
        message: `Monitoring started for "${room.name}" — polling every ${room.pollingIntervalSec}s`,
      },
    });

    return () => {
      engine.destroy();
      engineRef.current = null;
    };
  }, [room?.id, isConnected]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Post-cycle processing ─────────────────────────────────────────
  // Triggers after CYCLE_RESULT when cycleNumber increments.
  // Computes metrics, runs anomaly detectors, reconciles incidents,
  // updates baseline, dispatches CYCLE_COMPLETE, and auto-spawns
  // investigations for new anomalies.
  useEffect(() => {
    if (!room) return;
    if (state.cycleNumber === 0) return;
    if (state.cycleNumber <= cycleProcessedRef.current) return;
    // Only process after CYCLE_RESULT has populated aggregation data
    if (!state.lastCycleTimestamp) return;

    cycleProcessedRef.current = state.cycleNumber;

    // 1. Calculate dashboard metrics from aggregation data
    const windowSeconds = room.dataWindowMinutes * 60;
    const metrics = calculateMetrics(
      state.aggregation,
      state.heartbeat,
      state.metrics,      // previous cycle metrics for delta badges
      state.alerts,
      state.auditEntries,
      windowSeconds,
      ERROR_DIAGNOSIS_KB,
    );

    // 2. Run all 23 anomaly detectors
    const freshAnomalies = evaluateDetectors(
      metrics,
      state.latencyStats,
      state.baseline,
      room,
      state.botOverview,
      state.syntheticHealth,
      state.dnsHealth,
      state.alerts,
      state.rawLogSampleRate,
    );

    // 3. Reconcile anomalies — merge with existing, resolve gone ones
    const reconciledAnomalies = reconcileAnomalies(state.activeAnomalies, freshAnomalies);
    const activeAnomalies = reconciledAnomalies.filter(a => !a.resolved);

    // 4. Compute threat level
    const threatLevel = computeThreatLevel(activeAnomalies, state.alerts, state.incidents);

    // 5. Update baseline (EMA)
    const newBaseline = updateBaseline(
      metrics,
      state.latencyStats,
      state.baseline,
      state.rawLogSampleRate,
    );

    // 6. Reconcile incidents
    const incidents = reconcileIncidents(activeAnomalies, state.incidents);

    // 7. Dispatch CYCLE_COMPLETE to store all computed data
    dispatch({
      type: 'CYCLE_COMPLETE',
      payload: {
        metrics,
        anomalies: reconciledAnomalies,
        threatLevel,
        baseline: newBaseline,
        incidents,
      },
    });

    // 8. Persist baseline periodically
    if (state.cycleNumber % BASELINE_PERSIST_INTERVAL === 0 || state.cycleNumber === 1) {
      saveBaseline(room.id, newBaseline);
    }

    // 9. Add event feed entries for new anomalies
    const existingIds = new Set(state.activeAnomalies.map(a => a.detectorId));
    const brandNewAnomalies = activeAnomalies.filter(a => !existingIds.has(a.detectorId));

    for (const anomaly of brandNewAnomalies) {
      dispatch({
        type: 'ADD_EVENT',
        payload: {
          id: `anomaly-${anomaly.id}`,
          timestamp: new Date().toISOString(),
          type: 'alert',
          severity: anomaly.severity === 'CRITICAL' ? 'critical'
            : anomaly.severity === 'HIGH' ? 'error'
            : anomaly.severity === 'MEDIUM' ? 'warning'
            : 'info',
          message: `[${anomaly.detectorName}] ${anomaly.message}`,
        },
      });
    }

    // 10. Auto-spawn investigations for new HIGH/CRITICAL anomalies
    for (const anomaly of brandNewAnomalies) {
      if (anomaly.severity === 'CRITICAL' || anomaly.severity === 'HIGH') {
        const workflowId = DETECTOR_TO_WORKFLOW[anomaly.detectorId];
        if (!workflowId) continue;

        try {
          const investigation = createInvestigation(workflowId, anomaly.id);
          dispatch({ type: 'INVESTIGATION_UPDATE', payload: investigation });

          // Build investigation context
          const invContext = {
            namespace: room.namespace,
            room,
            aggregation: state.aggregation,
            latencyStats: state.latencyStats,
            alerts: state.alerts,
            auditEntries: state.auditEntries,
            onStepUpdate: (updated: Investigation) => {
              dispatch({ type: 'INVESTIGATION_UPDATE', payload: updated });
            },
          };

          // Execute investigation asynchronously
          executeInvestigation(investigation, invContext).then(completed => {
            dispatch({ type: 'INVESTIGATION_COMPLETE', payload: completed });
            dispatch({
              type: 'ADD_EVENT',
              payload: {
                id: `inv-complete-${completed.id}`,
                timestamp: new Date().toISOString(),
                type: 'investigation',
                severity: 'info',
                message: `Investigation complete: ${completed.finding?.rootCause ?? 'Analysis finished'}`,
              },
            });
          }).catch(() => {
            // Investigation errors are non-fatal
          });
        } catch {
          // Investigation creation errors are non-fatal
        }
      }
    }

    // 11. Toast for threat level escalation
    if (threatLevel !== state.threatLevel && threatLevel !== 'NOMINAL') {
      const labels: Record<ThreatLevel, string> = {
        NOMINAL: 'Nominal',
        ELEVATED: 'Elevated',
        HIGH: 'High',
        CRITICAL: 'Critical',
      };
      if (
        (['CRITICAL', 'HIGH', 'ELEVATED'] as ThreatLevel[]).indexOf(threatLevel) <
        (['CRITICAL', 'HIGH', 'ELEVATED'] as ThreatLevel[]).indexOf(state.threatLevel)
      ) {
        toast.error(`Threat level escalated to ${labels[threatLevel]}`);
      }
    }
  }, [state.cycleNumber, state.lastCycleTimestamp]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Visibility change handler ─────────────────────────────────────
  useEffect(() => {
    const handleVisibility = () => {
      const engine = engineRef.current;
      if (!engine) return;

      if (document.hidden) {
        engine.pause();
      } else {
        engine.resume();
      }
    };

    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, []);

  // ── Pause / Resume ────────────────────────────────────────────────
  const handleTogglePause = useCallback(() => {
    const engine = engineRef.current;
    if (!engine) return;

    if (engine.paused) {
      engine.resume();
      toast.success('Monitoring resumed');
    } else {
      engine.pause();
      toast.success('Monitoring paused');
    }
  }, [toast]);

  // ── Baseline Reset ────────────────────────────────────────────────
  const handleBaselineReset = useCallback(() => {
    dispatch({ type: 'BASELINE_RESET' });
    if (room) {
      saveBaseline(room.id, createEmptyBaseline());
      toast.success('Baseline reset — learning from scratch');
    }
  }, [room, toast]);

  // ── History Scrubber ──────────────────────────────────────────────
  const handleScrub = useCallback((index: number) => {
    const snap = state.snapshotHistory[index];
    if (!snap) return;
    dispatch({ type: 'SET_HISTORY_MODE', payload: { enabled: true, cursor: index } });
    dispatch({ type: 'APPLY_SNAPSHOT', payload: snap });
  }, [state.snapshotHistory]);

  const handleLive = useCallback(() => {
    dispatch({ type: 'SET_HISTORY_MODE', payload: { enabled: false } });
    // Re-apply latest snapshot to restore live data
    const latest = state.snapshotHistory[state.snapshotHistory.length - 1];
    if (latest) {
      dispatch({ type: 'APPLY_SNAPSHOT', payload: latest });
    }
  }, [state.snapshotHistory]);

  // ── Domain filter ─────────────────────────────────────────────────
  const domains = state.metrics.domainBreakdown.map(d => d.domain);
  const handleDomainChange = useCallback((domain: string | null) => {
    dispatch({ type: 'SET_DOMAIN_FILTER', payload: domain });
  }, []);

  // ── Cross-launch into other tools ─────────────────────────────────
  const handleCrossLaunch = useCallback((tool: string, context: Record<string, unknown>) => {
    navigate(`/${tool}`, { state: context });
  }, [navigate]);

  // ── Incident selection ────────────────────────────────────────────
  // Track selected incident for future detail panel expansion
  const [, setSelectedIncidentId] = useState<string | null>(null);

  // ── Export snapshot as JSON ───────────────────────────────────────
  const handleExportSnapshot = useCallback(() => {
    const data = {
      room: state.room,
      exportedAt: new Date().toISOString(),
      cycleNumber: state.cycleNumber,
      threatLevel: state.threatLevel,
      metrics: state.metrics,
      latencyStats: state.latencyStats,
      anomalies: state.activeAnomalies,
      incidents: state.incidents,
      aggregation: state.aggregation,
      eventFeed: state.eventFeed.slice(0, 100),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-snapshot-${state.room.name.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Snapshot exported');
  }, [state, toast]);

  // ── Early returns ─────────────────────────────────────────────────
  if (!room) {
    return (
      <div className="min-h-screen bg-[#0a0e1a] flex items-center justify-center text-gray-100">
        <div className="text-center">
          <p className="text-lg text-gray-400 mb-4">Room not found</p>
          <Link
            to="/soc-lobby"
            className="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-2 justify-center"
          >
            <ArrowLeft size={16} />
            Back to SOC Lobby
          </Link>
        </div>
      </div>
    );
  }

  if (!isConnected) {
    return (
      <div className="min-h-screen bg-[#0a0e1a] p-8">
        <div className="max-w-xl mx-auto">
          <Link
            to="/soc-lobby"
            className="flex items-center gap-2 text-sm text-gray-400 hover:text-cyan-400 transition-colors mb-6"
          >
            <ArrowLeft size={16} />
            Back to SOC Lobby
          </Link>
          <ConnectionPanel />
        </div>
      </div>
    );
  }

  const isPaused = state.pollingStatus === 'paused';
  const isError = state.pollingStatus === 'error';

  // ── Render ────────────────────────────────────────────────────────
  return (
    <SOCThemeWrapper threatLevel={state.threatLevel}>
      <div className="max-w-[1920px] mx-auto px-3 sm:px-4 lg:px-6 py-4">

        {/* ═══ Header Bar ═══════════════════════════════════════════ */}
        <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-3">
            <Link
              to="/soc-lobby"
              className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-cyan-400 transition-colors"
            >
              <ArrowLeft size={16} />
              Lobby
            </Link>
            <div className="h-5 w-px bg-[#1a2332]" />
            <h1 className="text-lg font-bold text-gray-100 tracking-wide">
              {room.name}
            </h1>
            {state.historyMode && (
              <span className="ml-2 px-2 py-0.5 rounded text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                HISTORY MODE
              </span>
            )}
            {isError && (
              <span className="ml-2 px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                ERROR
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Domain filter */}
            {domains.length > 1 && (
              <select
                value={state.selectedDomain ?? ''}
                onChange={e => handleDomainChange(e.target.value || null)}
                className="text-xs bg-[#0f1423] border border-[#1a2332] rounded-lg px-2 py-1.5 text-gray-300
                           focus:border-cyan-500/50 focus:outline-none"
              >
                <option value="">All domains</option>
                {domains.map(d => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            )}

            {/* History resume button */}
            {state.historyMode && (
              <button
                onClick={handleLive}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                           bg-green-500/10 border border-green-500/30 text-green-400
                           hover:bg-green-500/20 transition-all"
              >
                <Play size={12} />
                Go Live
              </button>
            )}

            {/* Pause / Resume */}
            <button
              onClick={handleTogglePause}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                isPaused
                  ? 'bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20'
                  : 'bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20'
              }`}
              title={isPaused ? 'Resume monitoring' : 'Pause monitoring'}
            >
              {isPaused ? <Play size={12} /> : <Pause size={12} />}
              {isPaused ? 'Resume' : 'Pause'}
            </button>

            {/* Baseline reset */}
            <button
              onClick={handleBaselineReset}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                         bg-[#1a2332] border border-[#283044] text-gray-400
                         hover:bg-[#222b3d] hover:text-gray-300 transition-all"
              title="Reset learned baseline"
            >
              <RotateCcw size={12} />
              Reset Baseline
            </button>

            {/* Export */}
            <button
              onClick={handleExportSnapshot}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                         bg-[#1a2332] border border-[#283044] text-gray-400
                         hover:bg-[#222b3d] hover:text-gray-300 transition-all"
              title="Export current snapshot as JSON"
            >
              <Download size={12} />
              Export
            </button>
          </div>
        </header>

        {/* ═══ Error Banner ═════════════════════════════════════════ */}
        {state.error && (
          <div className="mb-4 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            <strong>Polling error:</strong> {state.error}
          </div>
        )}

        {/* ═══ Bootstrap Loading ══════════════════════════════════ */}
        {state.cycleNumber === 0 && !state.error && (
          <div className="mb-4 px-6 py-8 rounded-xl bg-[#0f1423]/80 border border-cyan-500/20 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-cyan-500/10 mb-4">
              <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            </div>
            <h3 className="text-lg font-semibold text-cyan-400 mb-2">Bootstrapping SOC Room</h3>
            <p className="text-sm text-gray-400 max-w-md mx-auto">
              Loading last 5 minutes of access logs, security events, alerts, and aggregation data.
              Dashboard will populate momentarily.
            </p>
          </div>
        )}

        {/* ═══ Status Strip ═════════════════════════════════════════ */}
        <div className="mb-4">
          <StatusStrip
            metrics={state.metrics}
            heartbeat={state.heartbeat}
            latencyStats={state.latencyStats}
            threatLevel={state.threatLevel}
            countdown={state.nextCycleIn}
            pollingStatus={state.pollingStatus}
            rateState={engineRef.current?.rateState ?? 'green'}
            selectedDomain={state.selectedDomain}
            domains={domains}
            onDomainChange={handleDomainChange}
            historyMode={state.historyMode}
            room={room}
          />
        </div>

        {/* ═══ Main Dashboard Grid ══════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* ── Row 1: Traffic Time Series + Security Breakdown ───── */}
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Traffic Time Series
            </h3>
            <TrafficTimeSeries
              history={state.timeSeriesHistory}
              baseline={state.baseline}
            />
          </section>

          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Security Breakdown
            </h3>
            <SecurityBreakdown
              breakdown={state.metrics.securityBreakdown}
              topSignatures={state.metrics.topSignatures}
              topViolations={state.metrics.topViolations}
            />
          </section>

          {/* ── Row 2: Response Code Distribution + Attacker Table ── */}
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Response Code Distribution
            </h3>
            <ResponseCodeDist
              history={state.timeSeriesHistory}
              currentDist={state.metrics.responseCodeDist}
            />
          </section>

          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Top Attacking IPs
            </h3>
            {state.metrics.topAttackingIps.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 border-b border-[#1a2332]">
                      <th className="text-left py-2 pr-4 font-medium">IP Address</th>
                      <th className="text-left py-2 pr-4 font-medium">Country</th>
                      <th className="text-right py-2 font-medium">Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {state.metrics.topAttackingIps.slice(0, 15).map((ip, i) => (
                      <tr
                        key={`${ip.ip}-${i}`}
                        className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 transition-colors"
                      >
                        <td className="py-1.5 pr-4 font-mono text-red-400">{ip.ip}</td>
                        <td className="py-1.5 pr-4 text-gray-400">{ip.country ?? '—'}</td>
                        <td className="py-1.5 text-right text-gray-300">{ip.count.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500 text-xs">No attacking IPs detected</p>
            )}
          </section>

          {/* ── Row 3: Geo Distribution + Latency Waterfall ────────── */}
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Geographic Distribution
            </h3>
            {state.metrics.geoDistribution.length > 0 ? (
              <div className="space-y-1.5">
                {state.metrics.geoDistribution.slice(0, 15).map((geo, i) => (
                  <div key={`${geo.country}-${i}`} className="flex items-center gap-3">
                    <span className="text-xs text-gray-400 w-8 shrink-0">{geo.country}</span>
                    <div className="flex-1 bg-[#1a2332] rounded-full h-4 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          geo.isNew ? 'bg-yellow-500/80' : 'bg-cyan-500/60'
                        }`}
                        style={{ width: `${Math.min(100, geo.pct)}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 w-14 text-right shrink-0">
                      {geo.pct.toFixed(1)}%
                    </span>
                    <span className="text-xs text-gray-500 w-16 text-right shrink-0">
                      {geo.count.toLocaleString()}
                    </span>
                    {geo.isNew && (
                      <span className="text-[10px] font-medium text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded">
                        NEW
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-xs">No geo data available</p>
            )}
          </section>

          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Latency Waterfall
            </h3>
            <LatencyWaterfall
              waterfall={state.latencyStats.waterfall}
              perOrigin={state.latencyStats.perOrigin}
            />
          </section>

          {/* ── Error Diagnosis (full width) ───────────────────────── */}
          <section className={`${GLASS} lg:col-span-2`}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Error Diagnosis
            </h3>
            <ErrorDiagnosis
              diagnosis={state.metrics.errorDiagnosis}
              onInvestigate={(code: string) => {
                dispatch({
                  type: 'ADD_EVENT',
                  payload: {
                    id: `diag-${Date.now()}`,
                    timestamp: new Date().toISOString(),
                    type: 'investigation',
                    severity: 'info',
                    message: `Manual investigation triggered for error code ${code}`,
                  },
                });
              }}
            />
          </section>

          {/* ── Origin Health Grid (full width) ────────────────────── */}
          <section className={`${GLASS} lg:col-span-2`}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Origin Health
            </h3>
            <OriginHealthGrid
              origins={state.metrics.originHealth}
            />
          </section>

          {/* ── Hot Paths ──────────────────────────────────────────── */}
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Hot Paths
            </h3>
            {state.metrics.hotPaths.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 border-b border-[#1a2332]">
                      <th className="text-left py-2 pr-4 font-medium">Path</th>
                      <th className="text-right py-2 pr-4 font-medium">Requests</th>
                      <th className="text-right py-2 pr-4 font-medium">Errors</th>
                      <th className="text-right py-2 font-medium">Error %</th>
                    </tr>
                  </thead>
                  <tbody>
                    {state.metrics.hotPaths.slice(0, 15).map((p, i) => (
                      <tr
                        key={`${p.path}-${i}`}
                        className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 transition-colors"
                      >
                        <td className="py-1.5 pr-4 font-mono text-gray-300 max-w-[300px] truncate">
                          {p.path}
                        </td>
                        <td className="py-1.5 pr-4 text-right text-gray-400">
                          {p.count.toLocaleString()}
                        </td>
                        <td className="py-1.5 pr-4 text-right text-gray-400">
                          {p.errorCount.toLocaleString()}
                        </td>
                        <td className={`py-1.5 text-right font-medium ${
                          p.errorRate > 0.1 ? 'text-red-400' : p.errorRate > 0.05 ? 'text-yellow-400' : 'text-gray-400'
                        }`}>
                          {(p.errorRate * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500 text-xs">No path data available</p>
            )}
          </section>

          {/* ── Top Talkers ────────────────────────────────────────── */}
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Top Talkers (Source IPs)
            </h3>
            {state.metrics.topTalkers.length > 0 ? (
              <div className="space-y-1">
                {state.metrics.topTalkers.slice(0, 10).map((talker, i) => (
                  <div key={`${talker.ip}-${i}`} className="flex items-center gap-3">
                    <span className="text-xs font-mono text-gray-300 w-36 shrink-0 truncate">
                      {talker.ip}
                    </span>
                    <div className="flex-1 bg-[#1a2332] rounded-full h-3 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-500/60 transition-all duration-500"
                        style={{
                          width: `${Math.min(100,
                            state.metrics.topTalkers[0]?.count
                              ? (talker.count / state.metrics.topTalkers[0].count) * 100
                              : 0
                          )}%`,
                        }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 w-16 text-right shrink-0">
                      {talker.count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-xs">No source IP data available</p>
            )}
          </section>

          {/* ── Bot Intelligence (conditional) ─────────────────────── */}
          {room.features.botDefenseEnabled && state.botOverview && (
            <section className={`${GLASS} lg:col-span-2`}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Bot Intelligence
              </h3>
              <BotIntelligence data={state.botOverview} />
            </section>
          )}

          {/* ── CDN Monitor (conditional) ──────────────────────────── */}
          {room.cdnDistributions.length > 0 && state.metrics.cacheHitRatio !== null && (
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                CDN Monitor
              </h3>
              <CDNMonitor
                hitRatio={state.metrics.cacheHitRatio}
              />
            </section>
          )}

          {/* ── CSD Monitor (conditional) ──────────────────────────── */}
          {room.features.clientSideDefenseEnabled && state.csdSummary && (
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Client-Side Defense
              </h3>
              <CSDMonitor data={state.csdSummary} />
            </section>
          )}

          {/* ── DNS Health (conditional) ───────────────────────────── */}
          {room.dnsLoadBalancers.length > 0 && state.dnsHealth && (
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                DNS Health
              </h3>
              <div className="space-y-3">
                {state.dnsHealth.loadBalancers.map((lb, i) => (
                  <div key={`${lb.name}-${i}`} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${
                        lb.status === 'healthy' ? 'bg-green-400' :
                        lb.status === 'degraded' ? 'bg-yellow-400' : 'bg-red-400'
                      }`} />
                      <span className="text-xs text-gray-300">{lb.name}</span>
                    </div>
                    <span className={`text-xs font-medium uppercase ${
                      lb.status === 'healthy' ? 'text-green-400' :
                      lb.status === 'degraded' ? 'text-yellow-400' : 'text-red-400'
                    }`}>
                      {lb.status}
                    </span>
                  </div>
                ))}
                {state.dnsHealth.queryMetrics && (
                  <div className="mt-2 pt-2 border-t border-[#1a2332] flex items-center gap-4 text-xs text-gray-500">
                    <span>Queries: {state.dnsHealth.queryMetrics.totalQueries.toLocaleString()}</span>
                    <span>Errors: {state.dnsHealth.queryMetrics.errorCount.toLocaleString()}</span>
                    <span>Error Rate: {(state.dnsHealth.queryMetrics.errorRate * 100).toFixed(2)}%</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* ── InfraProtect (conditional) ─────────────────────────── */}
          {room.features.infraProtectEnabled && state.infraProtect && (
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Infrastructure Protection (L3/L4)
              </h3>
              <div className="space-y-3">
                {state.infraProtect.alerts.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1">Active Alerts</p>
                    {state.infraProtect.alerts.slice(0, 5).map((alert, i) => (
                      <div key={`${alert.id}-${i}`} className="flex items-center justify-between py-1 text-xs">
                        <span className="text-gray-300">{alert.targetNetwork}</span>
                        <span className={`font-medium uppercase ${
                          alert.severity === 'critical' ? 'text-red-400' :
                          alert.severity === 'major' ? 'text-yellow-400' : 'text-gray-400'
                        }`}>
                          {alert.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {state.infraProtect.activeMitigations.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-500 mb-1">Active Mitigations</p>
                    {state.infraProtect.activeMitigations.slice(0, 5).map((mit, i) => (
                      <div key={`${mit.id}-${i}`} className="flex items-center justify-between py-1 text-xs">
                        <span className="text-gray-300">{mit.targetNetwork}</span>
                        <span className="text-cyan-400">{mit.mitigatedIps} IPs blocked</span>
                      </div>
                    ))}
                  </div>
                )}
                {state.infraProtect.alerts.length === 0 && state.infraProtect.activeMitigations.length === 0 && (
                  <p className="text-gray-500 text-xs">No L3/L4 events detected</p>
                )}
              </div>
            </section>
          )}

          {/* ── Synthetic Health (conditional) ─────────────────────── */}
          {room.features.syntheticMonitorsEnabled && state.syntheticHealth && (
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Synthetic Monitoring
              </h3>
              <div className="space-y-3">
                {/* Global availability */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500">Global Availability</span>
                  <span className={`text-sm font-bold ${
                    state.syntheticHealth.globalAvailabilityPct >= 99 ? 'text-green-400' :
                    state.syntheticHealth.globalAvailabilityPct >= 95 ? 'text-yellow-400' : 'text-red-400'
                  }`}>
                    {state.syntheticHealth.globalAvailabilityPct.toFixed(1)}%
                  </span>
                </div>
                {/* Monitors */}
                {state.syntheticHealth.monitors.map((mon, i) => (
                  <div key={`${mon.name}-${i}`} className="flex items-center justify-between py-1">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${
                        mon.status === 'healthy' ? 'bg-green-400' :
                        mon.status === 'unhealthy' ? 'bg-red-400' : 'bg-gray-500'
                      }`} />
                      <span className="text-xs text-gray-300">{mon.name}</span>
                    </div>
                    <span className="text-xs text-gray-500">{mon.availabilityPct.toFixed(1)}%</span>
                  </div>
                ))}
                {/* TLS Certs */}
                {state.syntheticHealth.tlsCerts.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-[#1a2332]">
                    <p className="text-xs text-gray-500 mb-1">TLS Certificates</p>
                    {state.syntheticHealth.tlsCerts.map((cert, i) => (
                      <div key={`${cert.domain}-${i}`} className="flex items-center justify-between py-0.5 text-xs">
                        <span className="text-gray-300">{cert.domain}</span>
                        <span className={`font-medium ${
                          cert.status === 'ok' ? 'text-green-400' :
                          cert.status === 'warning' ? 'text-yellow-400' : 'text-red-400'
                        }`}>
                          {cert.daysUntilExpiry}d
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>
          )}
        </div>

        {/* ═══ Anomaly / Incident Section ═══════════════════════════ */}
        {(state.activeAnomalies.filter(a => !a.resolved).length > 0 || state.incidents.length > 0) && (
          <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Active Anomalies */}
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Active Anomalies ({state.activeAnomalies.filter(a => !a.resolved).length})
              </h3>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {state.activeAnomalies
                  .filter(a => !a.resolved)
                  .sort((a, b) => {
                    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3 };
                    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
                  })
                  .map(anomaly => (
                    <div
                      key={anomaly.id}
                      className={`p-3 rounded-lg border text-xs ${
                        anomaly.severity === 'CRITICAL' ? 'bg-red-500/5 border-red-500/30' :
                        anomaly.severity === 'HIGH' ? 'bg-orange-500/5 border-orange-500/30' :
                        anomaly.severity === 'MEDIUM' ? 'bg-yellow-500/5 border-yellow-500/30' :
                        'bg-blue-500/5 border-blue-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={`font-semibold ${
                          anomaly.severity === 'CRITICAL' ? 'text-red-400' :
                          anomaly.severity === 'HIGH' ? 'text-orange-400' :
                          anomaly.severity === 'MEDIUM' ? 'text-yellow-400' :
                          'text-blue-400'
                        }`}>
                          [{anomaly.severity}] {anomaly.detectorName}
                        </span>
                        <span className="text-gray-600 text-[10px]">
                          D{anomaly.detectorId}
                        </span>
                      </div>
                      <p className="text-gray-400">{anomaly.message}</p>
                      <div className="mt-1 flex items-center gap-3 text-gray-600">
                        <span>Value: {String(anomaly.triggerValue)}</span>
                        <span>Baseline: {String(anomaly.baselineValue)}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </section>

            {/* Incident Timeline */}
            <section className={GLASS}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Incidents ({state.incidents.filter(i => i.status !== 'resolved').length} active)
              </h3>
              <IncidentTimeline
                incidents={state.incidents}
                onSelect={(incident: Incident) => setSelectedIncidentId(incident.id)}
              />
            </section>
          </div>
        )}

        {/* ═══ Investigations ═══════════════════════════════════════ */}
        {(state.activeInvestigations.length > 0 || state.completedInvestigations.length > 0) && (
          <div className="mt-4">
            <section className={`${GLASS} lg:col-span-2`}>
              <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
                Investigations ({state.activeInvestigations.length} active, {state.completedInvestigations.length} completed)
              </h3>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {/* Active investigations */}
                {state.activeInvestigations.map(inv => (
                  <div
                    key={inv.id}
                    className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20 text-xs"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-cyan-400">
                        {inv.workflowId.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <span className="text-gray-500">
                        {inv.status === 'running' ? 'Running...' : inv.status}
                      </span>
                    </div>
                    {/* Steps progress */}
                    <div className="flex items-center gap-1">
                      {inv.steps.map((step) => (
                        <div
                          key={step.id}
                          className={`h-1.5 flex-1 rounded-full ${
                            step.status === 'complete' ? 'bg-green-500/60' :
                            step.status === 'running' ? 'bg-cyan-500/60 animate-pulse' :
                            step.status === 'error' ? 'bg-red-500/60' :
                            step.status === 'skipped' ? 'bg-gray-600' :
                            'bg-gray-700'
                          }`}
                          title={`${step.label}: ${step.status}`}
                        />
                      ))}
                    </div>
                    <p className="text-gray-500 mt-1.5">
                      Step {Math.min(inv.currentStepIndex + 1, inv.steps.length)}/{inv.steps.length}:{' '}
                      {inv.steps[inv.currentStepIndex]?.label ?? 'Pending'}
                    </p>
                  </div>
                ))}

                {/* Completed investigations */}
                {state.completedInvestigations.slice(0, 10).map(inv => (
                  <div
                    key={inv.id}
                    className="p-3 rounded-lg bg-[#1a2332]/50 border border-[#283044] text-xs"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-gray-400">
                        {inv.workflowId.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <span className={`text-xs ${
                        inv.status === 'complete' ? 'text-green-500' : 'text-red-400'
                      }`}>
                        {inv.status}
                      </span>
                    </div>
                    {inv.finding && (
                      <>
                        <p className="text-gray-300 mb-1">
                          <strong>Root cause:</strong> {inv.finding.rootCause}
                        </p>
                        <p className="text-gray-500">{inv.finding.evidenceSummary}</p>
                        {inv.finding.remediationActions.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {inv.finding.remediationActions.map((action, ai) => (
                              <button
                                key={ai}
                                onClick={() => {
                                  if (action.type === 'cross_launch' && action.targetTool) {
                                    handleCrossLaunch(action.targetTool, action.context ?? {});
                                  }
                                }}
                                className={`px-2 py-1 rounded text-[10px] font-medium transition-colors ${
                                  action.type === 'cross_launch'
                                    ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 cursor-pointer'
                                    : 'bg-[#1a2332] border border-[#283044] text-gray-400'
                                }`}
                              >
                                {action.label}
                              </button>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}

        {/* ═══ History Scrubber ══════════════════════════════════════ */}
        {state.snapshotHistory.length > 1 && (
          <div className="mt-4">
            <section className={GLASS}>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-gray-300 tracking-wide uppercase">
                  History Scrubber ({state.snapshotHistory.length} snapshots)
                </h3>
                {state.historyMode && (
                  <button
                    onClick={handleLive}
                    className="text-xs text-green-400 hover:text-green-300 transition-colors"
                  >
                    Return to Live
                  </button>
                )}
              </div>
              <div className="flex items-center gap-1">
                {state.snapshotHistory.map((snap, i) => {
                  const isActive = state.historyMode && state.historyCursor === i;
                  const color = snap.threatLevel === 'CRITICAL' ? 'bg-red-500'
                    : snap.threatLevel === 'HIGH' ? 'bg-orange-500'
                    : snap.threatLevel === 'ELEVATED' ? 'bg-yellow-500'
                    : 'bg-cyan-500';
                  return (
                    <button
                      key={snap.cycleNumber}
                      onClick={() => handleScrub(i)}
                      className={`flex-1 h-6 rounded-sm transition-all ${color} ${
                        isActive ? 'opacity-100 ring-1 ring-white/40' : 'opacity-30 hover:opacity-60'
                      }`}
                      title={`Cycle ${snap.cycleNumber} — ${new Date(snap.timestamp).toLocaleTimeString()} — ${snap.threatLevel}`}
                    />
                  );
                })}
              </div>
              {state.historyMode && state.historyCursor !== null && state.snapshotHistory[state.historyCursor] && (
                <div className="mt-2 text-xs text-gray-500 flex items-center gap-4">
                  <span>
                    Cycle {state.snapshotHistory[state.historyCursor].cycleNumber}
                  </span>
                  <span>
                    {new Date(state.snapshotHistory[state.historyCursor].timestamp).toLocaleString()}
                  </span>
                  <span className={`font-medium ${
                    state.snapshotHistory[state.historyCursor].threatLevel === 'CRITICAL' ? 'text-red-400' :
                    state.snapshotHistory[state.historyCursor].threatLevel === 'HIGH' ? 'text-orange-400' :
                    state.snapshotHistory[state.historyCursor].threatLevel === 'ELEVATED' ? 'text-yellow-400' :
                    'text-cyan-400'
                  }`}>
                    {state.snapshotHistory[state.historyCursor].threatLevel}
                  </span>
                </div>
              )}
            </section>
          </div>
        )}

        {/* ═══ Live Event Feed ══════════════════════════════════════ */}
        <div className="mt-4">
          <section className={GLASS}>
            <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
              Live Event Feed
            </h3>
            <LiveEventFeed
              events={state.eventFeed}
              maxVisible={200}
            />
          </section>
        </div>

        {/* ═══ Baseline Info Footer ═════════════════════════════════ */}
        <div className="mt-4 flex flex-wrap items-center gap-4 text-[10px] text-gray-600 px-1 pb-4">
          <span>Cycle #{state.cycleNumber}</span>
          <span>Baseline samples: {state.baseline.sampleCount}</span>
          <span>Baseline RPS: {state.baseline.avgRps.toFixed(1)} +/- {state.baseline.stdDevRps.toFixed(1)}</span>
          <span>Sample rate: {state.rawLogSampleRate.toFixed(1)}x</span>
          <span>JA4 clusters: {state.ja4Clusters.length}</span>
          {state.lastCycleTimestamp && (
            <span>Last cycle: {new Date(state.lastCycleTimestamp).toLocaleTimeString()}</span>
          )}
        </div>
      </div>
    </SOCThemeWrapper>
  );
}
