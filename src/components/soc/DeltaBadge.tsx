interface DeltaBadgeProps {
  current: number;
  previous: number;
  format?: 'number' | 'percent';
  inverse?: boolean;
}

export default function DeltaBadge({ current, previous, format = 'number', inverse = false }: DeltaBadgeProps) {
  const diff = current - previous;

  if (diff === 0 || (previous === 0 && current === 0)) {
    return (
      <span className="inline-flex items-center text-xs font-mono text-gray-500">
        &mdash;
      </span>
    );
  }

  const isPositive = diff > 0;
  // For normal metrics (like RPS), up = green. For inverse metrics (like error rate), up = red.
  const isGood = inverse ? !isPositive : isPositive;

  const absVal = Math.abs(diff);
  let displayVal: string;

  if (format === 'percent') {
    displayVal = absVal < 0.01 ? '<0.01%' : `${absVal.toFixed(2)}%`;
  } else {
    displayVal = absVal >= 1000
      ? `${(absVal / 1000).toFixed(1)}k`
      : absVal >= 1
        ? absVal.toFixed(1)
        : absVal.toFixed(2);
  }

  const arrow = isPositive ? '\u25B2' : '\u25BC';
  const colorClass = isGood ? 'text-[#00ff88]' : 'text-[#ff0040]';

  return (
    <span className={`inline-flex items-center gap-0.5 text-xs font-mono ${colorClass}`}>
      <span className="text-[10px]">{arrow}</span>
      {displayVal}
    </span>
  );
}
