// =============================================================================
// SOC Command Center — Multi-Room Lobby
// =============================================================================
// Route: /soc-lobby
// Displays all configured SOC monitoring rooms with live heartbeat status,
// supports room CRUD operations, and routes into individual SOC rooms.
// =============================================================================

import { useState, useEffect, useCallback, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Plus, Shield, ArrowLeft, Trash2, AlertTriangle, HelpCircle } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import SOCThemeWrapper from '../components/soc/SOCThemeWrapper';
import RoomCard from '../components/soc/RoomCard';
import RoomCreator from '../components/soc/RoomCreator';
import {
  getRooms, saveRoom, deleteRoom,
  type SOCRoomConfig, type LobbyRoomStatus, type ThreatLevel,
} from '../services/live-soc';
import { apiClient } from '../services/api';

// =============================================================================
// Constants
// =============================================================================

const HEARTBEAT_INTERVAL_MS = 60_000;
const GLASS = 'bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl';

// =============================================================================
// Helpers
// =============================================================================

function createDefaultStatus(roomId: string): LobbyRoomStatus {
  return {
    roomId,
    threatLevel: 'NOMINAL',
    rps: 0,
    errorRate: 0,
    incidentCount: 0,
    lastPollTimestamp: null,
    isPolling: false,
  };
}

/**
 * Computes the worst (highest) threat level across all rooms
 * for the wrapper ambient tint.
 */
function worstThreatLevel(statuses: Map<string, LobbyRoomStatus>): ThreatLevel {
  const order: Record<ThreatLevel, number> = {
    NOMINAL: 0,
    ELEVATED: 1,
    HIGH: 2,
    CRITICAL: 3,
  };
  let worst: ThreatLevel = 'NOMINAL';
  for (const status of statuses.values()) {
    if (order[status.threatLevel] > order[worst]) {
      worst = status.threatLevel;
    }
  }
  return worst;
}

/**
 * Lightweight heartbeat probe: 2 API calls (access_logs + security events)
 * to get RPS and basic error signal per room.
 */
async function probeRoom(
  room: SOCRoomConfig,
): Promise<{ rps: number; errorRate: number }> {
  const namespace = room.namespace;
  const endTime = new Date().toISOString();
  const startTime = new Date(Date.now() - room.dataWindowMinutes * 60 * 1000).toISOString();
  const windowSec = room.dataWindowMinutes * 60;

  const lbFilter = room.loadBalancers.length > 0
    ? `{${room.loadBalancers.map(lb => `vh_name=~"ves-io-http-loadbalancer-${lb}"`).join(' OR ')}}`
    : '{}';

  try {
    const [accessResp] = await Promise.all([
      apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/access_logs`,
        { namespace, query: lbFilter, start_time: startTime, end_time: endTime, limit: 1, scroll: false },
      ),
    ]);

    const totalHits = (accessResp as { total_hits?: number })?.total_hits ?? 0;
    const rps = windowSec > 0 ? totalHits / windowSec : 0;

    // Estimate error rate from a quick aggregation if available
    // For the lobby heartbeat we keep it minimal — full analysis only in SOCRoom
    return { rps, errorRate: 0 };
  } catch {
    return { rps: 0, errorRate: 0 };
  }
}

// =============================================================================
// Component
// =============================================================================

export function SOCLobby() {
  const navigate = useNavigate();
  const { isConnected } = useApp();
  const toast = useToast();

  // ---- State ----------------------------------------------------------------
  const [rooms, setRooms] = useState<SOCRoomConfig[]>([]);
  const [roomStatuses, setRoomStatuses] = useState<Map<string, LobbyRoomStatus>>(new Map());
  const [showCreator, setShowCreator] = useState(false);
  const [editRoom, setEditRoom] = useState<SOCRoomConfig | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Heartbeat interval refs
  const heartbeatTimers = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());
  const mountedRef = useRef(true);

  // ---- Load rooms from localStorage -----------------------------------------
  const loadRooms = useCallback(() => {
    const stored = getRooms();
    setRooms(stored);

    // Initialize statuses for any new rooms
    setRoomStatuses(prev => {
      const next = new Map(prev);
      for (const r of stored) {
        if (!next.has(r.id)) {
          next.set(r.id, createDefaultStatus(r.id));
        }
      }
      // Remove statuses for deleted rooms
      for (const key of next.keys()) {
        if (!stored.some(r => r.id === key)) {
          next.delete(key);
        }
      }
      return next;
    });
  }, []);

  useEffect(() => {
    loadRooms();
    return () => { mountedRef.current = false; };
  }, [loadRooms]);

  // ---- Background heartbeat per room ----------------------------------------
  const runHeartbeat = useCallback(async (room: SOCRoomConfig) => {
    if (!mountedRef.current || !isConnected) return;

    try {
      const result = await probeRoom(room);
      if (!mountedRef.current) return;

      setRoomStatuses(prev => {
        const next = new Map(prev);
        const existing = next.get(room.id) || createDefaultStatus(room.id);
        next.set(room.id, {
          ...existing,
          rps: result.rps,
          errorRate: result.errorRate,
          lastPollTimestamp: new Date().toISOString(),
          isPolling: false,
          // Keep threatLevel at NOMINAL for lobby — full detection only in SOCRoom
          threatLevel: 'NOMINAL',
        });
        return next;
      });
    } catch {
      // Silently ignore heartbeat failures in the lobby
    }
  }, [isConnected]);

  // Start/stop heartbeat intervals when rooms or connection state changes
  useEffect(() => {
    if (!isConnected) {
      // Clear all heartbeats when disconnected
      for (const timer of heartbeatTimers.current.values()) {
        clearInterval(timer);
      }
      heartbeatTimers.current.clear();
      return;
    }

    // Start heartbeats for rooms that don't have one yet
    for (const room of rooms) {
      if (!heartbeatTimers.current.has(room.id)) {
        // Run initial heartbeat immediately
        runHeartbeat(room);

        // Schedule recurring heartbeats
        const timer = setInterval(() => {
          runHeartbeat(room);
        }, HEARTBEAT_INTERVAL_MS);

        heartbeatTimers.current.set(room.id, timer);
      }
    }

    // Remove heartbeats for rooms that no longer exist
    for (const [roomId, timer] of heartbeatTimers.current.entries()) {
      if (!rooms.some(r => r.id === roomId)) {
        clearInterval(timer);
        heartbeatTimers.current.delete(roomId);
      }
    }

    return () => {
      for (const timer of heartbeatTimers.current.values()) {
        clearInterval(timer);
      }
      heartbeatTimers.current.clear();
    };
  }, [rooms, isConnected, runHeartbeat]);

  // ---- Room CRUD handlers ---------------------------------------------------
  const handleCreateRoom = useCallback(() => {
    setEditRoom(null);
    setShowCreator(true);
  }, []);

  const handleEditRoom = useCallback((room: SOCRoomConfig) => {
    setEditRoom(room);
    setShowCreator(true);
  }, []);

  const handleSaveRoom = useCallback((room: SOCRoomConfig) => {
    saveRoom(room);
    setShowCreator(false);
    setEditRoom(null);
    loadRooms();

    if (!editRoom) {
      // New room — navigate directly into it
      toast.success(`Room "${room.name}" created`);
      navigate(`/soc-room/${room.id}`);
    } else {
      toast.success(`Room "${room.name}" updated`);
    }
  }, [editRoom, loadRooms, navigate, toast]);

  const handleDeleteRoom = useCallback((roomId: string) => {
    setDeleteConfirmId(roomId);
  }, []);

  const confirmDelete = useCallback(() => {
    if (!deleteConfirmId) return;
    const room = rooms.find(r => r.id === deleteConfirmId);
    deleteRoom(deleteConfirmId);
    setDeleteConfirmId(null);
    loadRooms();
    toast.success(`Room "${room?.name ?? 'Unknown'}" deleted`);
  }, [deleteConfirmId, rooms, loadRooms, toast]);

  const handleEnterRoom = useCallback((roomId: string) => {
    // Update lastOpenedAt
    const room = rooms.find(r => r.id === roomId);
    if (room) {
      saveRoom({ ...room, lastOpenedAt: new Date().toISOString() });
    }
    navigate(`/soc-room/${roomId}`);
  }, [rooms, navigate]);

  const handleCancelCreator = useCallback(() => {
    setShowCreator(false);
    setEditRoom(null);
  }, []);

  // ---- Sort rooms: rooms with incidents first, then by last-opened ----------
  const sortedRooms = [...rooms].sort((a, b) => {
    const statusA = roomStatuses.get(a.id);
    const statusB = roomStatuses.get(b.id);
    const incidentA = statusA?.incidentCount ?? 0;
    const incidentB = statusB?.incidentCount ?? 0;

    // Rooms with incidents come first
    if (incidentA > 0 && incidentB === 0) return -1;
    if (incidentB > 0 && incidentA === 0) return 1;

    // Then by threat level (worst first)
    const threatOrder: Record<ThreatLevel, number> = { NOMINAL: 0, ELEVATED: 1, HIGH: 2, CRITICAL: 3 };
    const threatA = threatOrder[statusA?.threatLevel ?? 'NOMINAL'];
    const threatB = threatOrder[statusB?.threatLevel ?? 'NOMINAL'];
    if (threatA !== threatB) return threatB - threatA;

    // Then by lastOpenedAt (most recent first)
    return new Date(b.lastOpenedAt).getTime() - new Date(a.lastOpenedAt).getTime();
  });

  // ---- Compute wrapper threat level -----------------------------------------
  const wrapperThreatLevel = worstThreatLevel(roomStatuses);

  // ---- Render ---------------------------------------------------------------
  return (
    <SOCThemeWrapper threatLevel={wrapperThreatLevel}>
      <div className="max-w-[1800px] mx-auto px-4 sm:px-6 lg:px-8 py-6">

        {/* ── Header ──────────────────────────────────────────────────── */}
        <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-cyan-400 transition-colors"
            >
              <ArrowLeft size={16} />
              Back to Apps
            </Link>
            <div className="h-6 w-px bg-[#1a2332]" />
            <div className="flex items-center gap-2">
              <Shield className="text-cyan-400" size={22} />
              <h1 className="text-xl font-bold tracking-wider text-gray-100 uppercase">
                SOC Command Center
              </h1>
            </div>
            <Link to="/explainer/soc-room" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
              <HelpCircle className="w-3.5 h-3.5" /> How does this work?
            </Link>
          </div>

          {isConnected && (
            <button
              onClick={handleCreateRoom}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                         bg-cyan-500/10 border border-cyan-500/30 text-cyan-400
                         hover:bg-cyan-500/20 transition-all"
            >
              <Plus size={16} />
              Create Room
            </button>
          )}
        </header>

        {/* ── Connection Gate ─────────────────────────────────────────── */}
        {!isConnected ? (
          <div className="max-w-xl mx-auto mt-12">
            <ConnectionPanel />
          </div>
        ) : (
          <>
            {/* ── Room Grid ─────────────────────────────────────────── */}
            {sortedRooms.length === 0 ? (
              <div className={`${GLASS} p-12 text-center`}>
                <Shield className="mx-auto mb-4 text-gray-600" size={48} />
                <p className="text-gray-400 text-lg mb-2">
                  No rooms configured
                </p>
                <p className="text-gray-500 text-sm mb-6">
                  Create your first SOC room to begin monitoring load balancers, security events, and anomalies.
                </p>
                <button
                  onClick={handleCreateRoom}
                  className="inline-flex items-center gap-2 px-6 py-3 rounded-lg text-sm font-medium
                             bg-cyan-500/10 border border-cyan-500/30 text-cyan-400
                             hover:bg-cyan-500/20 transition-all"
                >
                  <Plus size={16} />
                  Create Your First Room
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {sortedRooms.map(room => (
                  <RoomCard
                    key={room.id}
                    room={room}
                    status={roomStatuses.get(room.id) || createDefaultStatus(room.id)}
                    onEnter={handleEnterRoom}
                    onEdit={handleEditRoom}
                    onDelete={handleDeleteRoom}
                  />
                ))}
              </div>
            )}

            {/* ── Lobby Footer Stats ────────────────────────────────── */}
            {sortedRooms.length > 0 && (
              <div className="mt-6 flex items-center gap-6 text-xs text-gray-500">
                <span>{sortedRooms.length} room{sortedRooms.length !== 1 ? 's' : ''} configured</span>
                <span className="h-3 w-px bg-[#1a2332]" />
                <span>Heartbeat every {HEARTBEAT_INTERVAL_MS / 1000}s</span>
                <span className="h-3 w-px bg-[#1a2332]" />
                <span>
                  {Array.from(roomStatuses.values()).filter(s => s.lastPollTimestamp).length} room{
                    Array.from(roomStatuses.values()).filter(s => s.lastPollTimestamp).length !== 1 ? 's' : ''
                  } reporting
                </span>
              </div>
            )}
          </>
        )}

        {/* ── Room Creator Modal ──────────────────────────────────────── */}
        {showCreator && (
          <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto">
            {/* Backdrop */}
            <div
              className="fixed inset-0 bg-black/60 backdrop-blur-sm"
              onClick={handleCancelCreator}
            />
            {/* Modal content */}
            <div className="relative z-10 w-full max-w-2xl my-8 mx-4">
              <div className={`${GLASS} p-6 shadow-2xl`}>
                <RoomCreator
                  onSave={handleSaveRoom}
                  onCancel={handleCancelCreator}
                  editRoom={editRoom}
                />
              </div>
            </div>
          </div>
        )}

        {/* ── Delete Confirmation Modal ───────────────────────────────── */}
        {deleteConfirmId && (
          <div className="fixed inset-0 z-50 flex items-center justify-center">
            <div
              className="fixed inset-0 bg-black/60 backdrop-blur-sm"
              onClick={() => setDeleteConfirmId(null)}
            />
            <div className={`relative z-10 ${GLASS} p-6 max-w-md mx-4 shadow-2xl`}>
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="text-red-400" size={24} />
                <h3 className="text-lg font-semibold text-gray-100">Delete Room</h3>
              </div>
              <p className="text-gray-400 text-sm mb-6">
                Are you sure you want to delete{' '}
                <span className="text-gray-200 font-medium">
                  {rooms.find(r => r.id === deleteConfirmId)?.name ?? 'this room'}
                </span>
                ? This will remove all saved baselines and cannot be undone.
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setDeleteConfirmId(null)}
                  className="px-4 py-2 rounded-lg text-sm text-gray-400
                             bg-[#1a2332] hover:bg-[#222b3d] transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmDelete}
                  className="px-4 py-2 rounded-lg text-sm font-medium text-white
                             bg-red-600/80 hover:bg-red-600 transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Trash2 size={14} />
                    Delete Room
                  </span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </SOCThemeWrapper>
  );
}
