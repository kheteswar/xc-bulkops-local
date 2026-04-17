import React, { useRef, useState, useMemo } from 'react';
import { AlertTriangle, CheckCircle, Search, ChevronRight } from 'lucide-react';
import type { Incident, AnomalySeverity } from '../../services/live-soc/types';

interface IncidentTimelineProps {
  incidents: Incident[];
  onSelect?: (incident: Incident) => void;
}

const SEVERITY_COLORS: Record<AnomalySeverity, string> = {
  CRITICAL: '#ff0040',
  HIGH: '#ff6b35',
  MEDIUM: '#ffbe0b',
  INFO: '#00d4ff',
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  active: <AlertTriangle className="w-3 h-3" />,
  investigating: <Search className="w-3 h-3" />,
  resolved: <CheckCircle className="w-3 h-3" />,
};

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
}

function formatDate(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  } catch {
    return ts;
  }
}

export default function IncidentTimeline({ incidents, onSelect }: IncidentTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const sorted = useMemo(
    () =>
      [...incidents].sort(
        (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
      ),
    [incidents],
  );

  const selectedIncident = useMemo(
    () => sorted.find((i) => i.id === selectedId) ?? null,
    [sorted, selectedId],
  );

  const handleClick = (incident: Incident) => {
    setSelectedId(selectedId === incident.id ? null : incident.id);
    onSelect?.(incident);
  };

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
        Incident Timeline
      </h3>

      {sorted.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-gray-600 text-sm font-mono">
          No incidents recorded
        </div>
      ) : (
        <>
          {/* Scrollable horizontal timeline */}
          <div ref={scrollRef} className="overflow-x-auto pb-2 scrollbar-thin">
            <div className="relative min-w-max px-4" style={{ minHeight: 90 }}>
              {/* Timeline bar */}
              <div className="absolute left-4 right-4 top-10 h-px bg-[#1a2332]" />

              {/* Time markers and dots */}
              <div className="flex items-start gap-6">
                {sorted.map((incident) => {
                  const color = SEVERITY_COLORS[incident.severity];
                  const isActive = incident.status !== 'resolved';
                  const isSelected = selectedId === incident.id;

                  return (
                    <div
                      key={incident.id}
                      className="flex flex-col items-center cursor-pointer group"
                      style={{ minWidth: 70 }}
                      onClick={() => handleClick(incident)}
                    >
                      {/* Time label */}
                      <span className="text-[9px] font-mono text-gray-600 mb-1">
                        {formatDate(incident.createdAt)}
                      </span>
                      <span className="text-[10px] font-mono text-gray-500 mb-2">
                        {formatTime(incident.createdAt)}
                      </span>

                      {/* Dot */}
                      <div className="relative">
                        {/* Pulse ring for active incidents */}
                        {isActive && (
                          <div
                            className="absolute inset-0 rounded-full animate-ping"
                            style={{
                              backgroundColor: color,
                              opacity: 0.3,
                              animationDuration: '2s',
                            }}
                          />
                        )}
                        <div
                          className={`relative w-5 h-5 rounded-full flex items-center justify-center border-2 transition-transform ${
                            isSelected ? 'scale-125' : 'group-hover:scale-110'
                          }`}
                          style={{
                            borderColor: color,
                            backgroundColor: isActive ? color + '33' : '#0a0e1a',
                            boxShadow: isSelected ? `0 0 12px ${color}66` : `0 0 6px ${color}33`,
                          }}
                        >
                          <span style={{ color }}>{STATUS_ICONS[incident.status]}</span>
                        </div>
                      </div>

                      {/* Title */}
                      <span
                        className="mt-2 text-[10px] text-center leading-tight max-w-[80px] truncate"
                        style={{ color: isSelected ? color : '#9ca3af' }}
                        title={incident.title}
                      >
                        {incident.title}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Expanded details */}
          {selectedIncident && (
            <div
              className="mt-3 p-3 bg-[#0a0e1a]/60 border rounded-lg transition-all"
              style={{ borderColor: SEVERITY_COLORS[selectedIncident.severity] + '33' }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="text-xs font-semibold"
                      style={{ color: SEVERITY_COLORS[selectedIncident.severity] }}
                    >
                      [{selectedIncident.severity}]
                    </span>
                    <span className="text-sm text-gray-200 font-semibold truncate">
                      {selectedIncident.title}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">{selectedIncident.summary}</p>
                  <div className="flex items-center gap-3 mt-2 text-[10px] text-gray-600 font-mono">
                    <span>Status: {selectedIncident.status}</span>
                    <span>Anomalies: {selectedIncident.anomalyIds.length}</span>
                    <span>Investigations: {selectedIncident.investigationIds.length}</span>
                    {selectedIncident.resolvedAt && (
                      <span>Resolved: {formatTime(selectedIncident.resolvedAt)}</span>
                    )}
                  </div>
                </div>
                {onSelect && (
                  <button
                    onClick={() => onSelect(selectedIncident)}
                    className="flex items-center gap-1 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-[#00d4ff] bg-[#00d4ff]/10 border border-[#00d4ff]/20 rounded hover:bg-[#00d4ff]/20 transition-colors flex-shrink-0"
                  >
                    Details <ChevronRight className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
