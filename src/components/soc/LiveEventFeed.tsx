import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Lock, Unlock, Terminal } from 'lucide-react';
import type { EventFeedEntry, EventFeedEntryType } from '../../services/live-soc/types';

interface LiveEventFeedProps {
  events: EventFeedEntry[];
  maxVisible?: number;
}

type FilterTab = 'all' | 'security' | 'error' | 'bot' | 'dns';

const FILTER_TABS: Array<{ id: FilterTab; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'security', label: 'Security' },
  { id: 'error', label: 'Errors' },
  { id: 'bot', label: 'Bot' },
  { id: 'dns', label: 'DNS' },
];

const FILTER_MAP: Record<FilterTab, EventFeedEntryType[] | null> = {
  all: null,
  security: ['security', 'alert'],
  error: ['error'],
  bot: ['bot'],
  dns: ['dns'],
};

const TYPE_COLORS: Record<EventFeedEntryType, string> = {
  access: 'text-gray-500',
  security: 'text-[#ff0040]',
  error: 'text-[#ffbe0b]',
  bot: 'text-purple-400',
  dns: 'text-[#00d4ff]',
  config: 'text-blue-400',
  alert: 'text-orange-400',
  investigation: 'text-[#00d4ff]',
};

const SEVERITY_STYLES: Record<string, string> = {
  info: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  warning: 'bg-[#ffbe0b]/15 text-[#ffbe0b] border-[#ffbe0b]/30',
  error: 'bg-[#ff0040]/15 text-[#ff0040] border-[#ff0040]/30',
  critical: 'bg-[#ff0040]/20 text-[#ff0040] border-[#ff0040]/40',
};

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  return (
    <span className={`inline-flex px-1 py-px rounded text-[9px] font-semibold uppercase tracking-wider border ${style}`}>
      {severity}
    </span>
  );
}

export default function LiveEventFeed({ events, maxVisible = 200 }: LiveEventFeedProps) {
  const [activeFilter, setActiveFilter] = useState<FilterTab>('all');
  const [scrollLocked, setScrollLocked] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const wasLockedRef = useRef(true);

  const filtered = React.useMemo(() => {
    const types = FILTER_MAP[activeFilter];
    const items = types ? events.filter((e) => types.includes(e.type)) : events;
    return items.slice(-maxVisible);
  }, [events, activeFilter, maxVisible]);

  // Auto-scroll to bottom when locked and new events arrive
  useEffect(() => {
    if (scrollLocked && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filtered, scrollLocked]);

  // Detect manual scroll to auto-unlock
  const handleScroll = useCallback(() => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 40;

    if (isAtBottom && !wasLockedRef.current) {
      setScrollLocked(true);
      wasLockedRef.current = true;
    } else if (!isAtBottom && wasLockedRef.current) {
      setScrollLocked(false);
      wasLockedRef.current = false;
    }
  }, []);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl overflow-hidden flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#1a2332]">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-300 tracking-wide uppercase">
            Live Event Feed
          </h3>
          <span className="text-[10px] font-mono text-gray-600">
            ({filtered.length})
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Filter tabs */}
          <div className="flex items-center gap-0.5 bg-[#0a0e1a] rounded-lg p-0.5">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveFilter(tab.id)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider transition-colors ${
                  activeFilter === tab.id
                    ? 'bg-[#1a2332] text-gray-200'
                    : 'text-gray-500 hover:text-gray-400'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Scroll lock toggle */}
          <button
            onClick={() => {
              setScrollLocked(!scrollLocked);
              wasLockedRef.current = !scrollLocked;
              if (!scrollLocked && scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
              }
            }}
            className={`p-1 rounded transition-colors ${
              scrollLocked
                ? 'text-[#00ff88] hover:bg-[#00ff88]/10'
                : 'text-gray-500 hover:bg-[#1a2332]'
            }`}
            title={scrollLocked ? 'Auto-scroll ON' : 'Auto-scroll OFF'}
          >
            {scrollLocked ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Event list */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="relative flex-1 overflow-y-auto min-h-[200px] max-h-[400px] bg-[#080c15]"
        style={{ fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace' }}
      >
        {/* CRT scanline overlay */}
        <div
          className="pointer-events-none absolute inset-0 z-10 opacity-[0.03]"
          style={{
            backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 1px, rgba(0,212,255,0.08) 1px, rgba(0,212,255,0.08) 2px)',
            animation: 'soc-scanline 8s linear infinite',
          }}
        />

        <div className="relative z-0 p-2 space-y-px">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center py-10 text-gray-600 text-xs">
              No events to display
            </div>
          ) : (
            filtered.map((event) => (
              <div
                key={event.id}
                className="flex items-start gap-2 px-2 py-0.5 hover:bg-[#1a2332]/20 rounded transition-colors"
              >
                <span className="text-[10px] text-gray-600 flex-shrink-0 mt-px w-16 text-right">
                  {formatTimestamp(event.timestamp)}
                </span>
                <SeverityBadge severity={event.severity} />
                <span className={`text-[10px] uppercase font-semibold flex-shrink-0 w-14 ${TYPE_COLORS[event.type]}`}>
                  {event.type}
                </span>
                <span className="text-xs text-gray-300 break-all leading-tight">
                  {event.message}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      <style>{`
        @keyframes soc-scanline {
          0% { transform: translateY(0); }
          100% { transform: translateY(100%); }
        }
      `}</style>
    </div>
  );
}
