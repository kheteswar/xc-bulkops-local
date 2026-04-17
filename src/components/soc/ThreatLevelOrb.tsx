import { useMemo } from 'react';
import { THREAT_COLORS } from '../../services/live-soc/types';
import type { ThreatLevel } from '../../services/live-soc/types';

interface ThreatLevelOrbProps {
  level: ThreatLevel;
  size?: 'sm' | 'md' | 'lg';
}

const SIZE_MAP: Record<'sm' | 'md' | 'lg', number> = {
  sm: 24,
  md: 40,
  lg: 64,
};

const PULSE_SPEED: Record<ThreatLevel, string> = {
  NOMINAL: '3s',
  ELEVATED: '1.5s',
  HIGH: '0.8s',
  CRITICAL: '0.4s',
};

export default function ThreatLevelOrb({ level, size = 'md' }: ThreatLevelOrbProps) {
  const px = SIZE_MAP[size];
  const color = THREAT_COLORS[level];
  const speed = PULSE_SPEED[level];

  const animationName = useMemo(() => `soc-orb-pulse-${level}`, [level]);

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: px, height: px }}>
      {/* Glow layer */}
      <div
        className="absolute inset-0 rounded-full"
        style={{
          backgroundColor: color,
          opacity: 0.15,
          filter: `blur(${px * 0.4}px)`,
          animation: `${animationName} ${speed} ease-in-out infinite`,
        }}
      />

      {/* Orb body */}
      <div
        className="relative rounded-full"
        style={{
          width: px,
          height: px,
          background: `radial-gradient(circle at 35% 35%, ${color}cc, ${color}66 50%, ${color}33 75%, ${color}11)`,
          boxShadow: `
            0 0 ${px * 0.3}px ${color}66,
            0 0 ${px * 0.6}px ${color}33,
            inset 0 0 ${px * 0.2}px ${color}44
          `,
          animation: `${animationName} ${speed} ease-in-out infinite`,
        }}
      />

      {/* Highlight dot */}
      <div
        className="absolute rounded-full bg-white"
        style={{
          width: px * 0.15,
          height: px * 0.15,
          top: px * 0.22,
          left: px * 0.3,
          opacity: 0.6,
        }}
      />

      <style>{`
        @keyframes ${animationName} {
          0%, 100% {
            transform: scale(1);
            opacity: 1;
          }
          50% {
            transform: scale(1.15);
            opacity: 0.7;
          }
        }
      `}</style>
    </div>
  );
}
