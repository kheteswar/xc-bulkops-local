import React from 'react';
import type { ThreatLevel } from '../../services/live-soc/types';

interface SOCThemeWrapperProps {
  children: React.ReactNode;
  threatLevel: ThreatLevel;
}

const AMBIENT_TINTS: Record<ThreatLevel, string> = {
  NOMINAL: 'rgba(0, 100, 180, 0.04)',
  ELEVATED: 'rgba(255, 190, 11, 0.05)',
  HIGH: 'rgba(255, 107, 53, 0.06)',
  CRITICAL: 'rgba(255, 0, 64, 0.08)',
};

const PULSE_CLASSNAMES: Record<ThreatLevel, string> = {
  NOMINAL: '',
  ELEVATED: '',
  HIGH: '',
  CRITICAL: 'animate-[soc-critical-pulse_2s_ease-in-out_infinite]',
};

export default function SOCThemeWrapper({ children, threatLevel }: SOCThemeWrapperProps) {
  return (
    <div
      data-theme="dark"
      className={`relative min-h-screen overflow-hidden ${PULSE_CLASSNAMES[threatLevel]}`}
      style={{ backgroundColor: '#0a0e1a' }}
    >
      {/* Hexagonal grid pattern overlay */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.035]"
        style={{
          backgroundImage: `
            radial-gradient(circle, #00d4ff 1px, transparent 1px),
            radial-gradient(circle, #00d4ff 1px, transparent 1px)
          `,
          backgroundSize: '60px 52px',
          backgroundPosition: '0 0, 30px 26px',
        }}
      />

      {/* Ambient threat-level tint */}
      <div
        className="pointer-events-none absolute inset-0 transition-colors duration-[2000ms]"
        style={{ backgroundColor: AMBIENT_TINTS[threatLevel] }}
      />

      {/* Content */}
      <div className="relative z-10 text-gray-100">
        {children}
      </div>

      {/* Inline keyframes for critical pulse */}
      <style>{`
        @keyframes soc-critical-pulse {
          0%, 100% { box-shadow: inset 0 0 60px rgba(255, 0, 64, 0); }
          50% { box-shadow: inset 0 0 120px rgba(255, 0, 64, 0.12); }
        }
      `}</style>
    </div>
  );
}
