import React, { useEffect, useState } from 'react';

const colorFor = (verdict) => {
  if (verdict === 'PHISHING') {
    return { stroke: '#ef4444', glow: 'rgba(239,68,68,0.6)', label: 'text-red-400' };
  }
  if (verdict === 'SOSPECHOSO') {
    return { stroke: '#f59e0b', glow: 'rgba(245,158,11,0.55)', label: 'text-amber-400' };
  }
  return { stroke: '#10b981', glow: 'rgba(16,185,129,0.55)', label: 'text-emerald-400' };
};

const labelForScore = (score) => {
  if (score <= 30) return 'Bajo riesgo';
  if (score <= 60) return 'Riesgo moderado';
  return 'Alto riesgo';
};

export default function ScoreGauge({ score = 0, verdict = 'SOSPECHOSO' }) {
  const [animated, setAnimated] = useState(0);
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const { stroke, glow, label } = colorFor(verdict);

  useEffect(() => {
    const t = setTimeout(() => setAnimated(safeScore), 80);
    return () => clearTimeout(t);
  }, [safeScore]);

  const r = 80;
  const c = Math.PI * r;
  const offset = c - (animated / 100) * c;
  const pulsing = safeScore > 60;
  const gradId = `gauge-${verdict.replace(/\s/g, '')}`;

  return (
    <div
      className="relative flex flex-col items-center"
      aria-label={`Score ${safeScore} de 100`}
    >
      <svg
        viewBox="0 0 200 110"
        className="w-full max-w-[280px]"
        style={pulsing ? { filter: `drop-shadow(0 0 18px ${glow})` } : undefined}
      >
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={stroke} stopOpacity="0.7" />
            <stop offset="100%" stopColor={stroke} stopOpacity="1" />
          </linearGradient>
        </defs>
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="14"
          strokeLinecap="round"
        />
        <path
          d="M 20 100 A 80 80 0 0 1 180 100"
          fill="none"
          stroke={`url(#${gradId})`}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.22, 1, 0.36, 1)' }}
        />
      </svg>
      <div className="-mt-12 flex flex-col items-center">
        <div className={`font-display text-5xl font-bold tabular-nums ${label}`}>
          {Math.round(animated)}
        </div>
        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Riesgo / 100</div>
        <div className="mt-1 text-[10px] text-slate-600">{labelForScore(safeScore)}</div>
      </div>
    </div>
  );
}
