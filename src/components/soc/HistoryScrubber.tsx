import { useCallback } from 'react';
import { History, ChevronLeft, ChevronRight } from 'lucide-react';
import type { CycleSnapshot } from '../../services/live-soc/types';

interface HistoryScrubberProps {
  snapshots: CycleSnapshot[];
  currentCursor: number | null;
  historyMode: boolean;
  onScrub: (index: number) => void;
  onLive: () => void;
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function formatShortTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
}

function threatLevelColor(level: string): string {
  switch (level) {
    case 'NOMINAL':
      return '#00ff88';
    case 'ELEVATED':
      return '#ffbe0b';
    case 'HIGH':
      return '#ff6b35';
    case 'CRITICAL':
      return '#ff0040';
    default:
      return '#6b7280';
  }
}

export default function HistoryScrubber({
  snapshots,
  currentCursor,
  historyMode,
  onScrub,
  onLive,
}: HistoryScrubberProps) {
  const currentIndex = currentCursor ?? snapshots.length - 1;
  const currentSnapshot = snapshots[currentIndex] ?? null;

  const canGoBack = currentIndex > 0;
  const canGoForward = currentIndex < snapshots.length - 1;

  const handleSliderChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = parseInt(e.target.value, 10);
      onScrub(val);
    },
    [onScrub]
  );

  const handleStepBack = useCallback(() => {
    if (canGoBack) onScrub(currentIndex - 1);
  }, [canGoBack, currentIndex, onScrub]);

  const handleStepForward = useCallback(() => {
    if (canGoForward) onScrub(currentIndex + 1);
  }, [canGoForward, currentIndex, onScrub]);

  // Time range display
  const firstTs = snapshots[0]?.timestamp;
  const lastTs = snapshots[snapshots.length - 1]?.timestamp;

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-200">History</h3>
          {historyMode && (
            <span className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded bg-[#ffbe0b]/10 text-[#ffbe0b] border border-[#ffbe0b]/30">
              Reviewing
            </span>
          )}
        </div>

        {/* LIVE button */}
        <button
          onClick={onLive}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
            !historyMode
              ? 'bg-[#00ff88]/15 text-[#00ff88] border border-[#00ff88]/30 cursor-default'
              : 'bg-[#1a2332] text-gray-400 border border-[#1a2332] hover:bg-[#00ff88]/10 hover:text-[#00ff88] hover:border-[#00ff88]/30'
          }`}
        >
          <span className="relative flex h-2 w-2">
            {!historyMode && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff88] opacity-75" />
            )}
            <span
              className={`relative inline-flex rounded-full h-2 w-2 ${
                !historyMode ? 'bg-[#00ff88]' : 'bg-gray-500'
              }`}
            />
          </span>
          LIVE
        </button>
      </div>

      {snapshots.length === 0 ? (
        <div className="flex items-center justify-center py-4 text-gray-500">
          <p className="text-xs">No snapshots recorded yet</p>
        </div>
      ) : (
        <>
          {/* Slider area */}
          <div className="relative">
            {/* Threat level dots above slider */}
            <div className="flex justify-between mb-1 px-1">
              {snapshots.map((snap, i) => {
                const isActive = i === currentIndex;
                return (
                  <div
                    key={i}
                    className="flex flex-col items-center"
                    style={{ width: snapshots.length <= 1 ? '100%' : undefined }}
                  >
                    <span
                      className={`inline-block w-1.5 h-1.5 rounded-full transition-all ${
                        isActive ? 'w-2.5 h-2.5' : ''
                      }`}
                      style={{
                        backgroundColor: threatLevelColor(snap.threatLevel),
                        boxShadow: isActive
                          ? `0 0 8px ${threatLevelColor(snap.threatLevel)}80`
                          : undefined,
                      }}
                    />
                  </div>
                );
              })}
            </div>

            {/* Range slider */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleStepBack}
                disabled={!canGoBack}
                className="p-1 rounded hover:bg-[#1a2332] transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4 text-gray-400" />
              </button>

              <div className="flex-1 relative">
                <input
                  type="range"
                  min={0}
                  max={snapshots.length - 1}
                  value={currentIndex}
                  onChange={handleSliderChange}
                  className="w-full h-1.5 rounded-full appearance-none cursor-pointer bg-[#1a2332]"
                  style={{
                    accentColor: historyMode ? '#ffbe0b' : '#00d4ff',
                  }}
                />
              </div>

              <button
                onClick={handleStepForward}
                disabled={!canGoForward}
                className="p-1 rounded hover:bg-[#1a2332] transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4 text-gray-400" />
              </button>
            </div>

            {/* Time range labels */}
            <div className="flex justify-between mt-1 px-7">
              <span className="text-[10px] font-mono text-gray-600">
                {firstTs ? formatShortTime(firstTs) : '—'}
              </span>
              <span className="text-[10px] font-mono text-gray-600">
                {lastTs ? formatShortTime(lastTs) : '—'}
              </span>
            </div>
          </div>

          {/* Current snapshot info */}
          {currentSnapshot && (
            <div className="mt-3 pt-3 border-t border-[#1a2332]">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Timestamp</span>
                    <p className="text-xs font-mono text-gray-300">
                      {formatTimestamp(currentSnapshot.timestamp)}
                    </p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Cycle</span>
                    <p className="text-xs font-mono text-gray-300">
                      #{currentSnapshot.cycleNumber}
                    </p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Threat</span>
                    <p
                      className="text-xs font-mono font-semibold"
                      style={{ color: threatLevelColor(currentSnapshot.threatLevel) }}
                    >
                      {currentSnapshot.threatLevel}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3 text-right">
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">RPS</span>
                    <p className="text-xs font-mono text-gray-300">
                      {currentSnapshot.heartbeat.rps.toFixed(1)}
                    </p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Position</span>
                    <p className="text-xs font-mono text-gray-300">
                      {currentIndex + 1} / {snapshots.length}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
