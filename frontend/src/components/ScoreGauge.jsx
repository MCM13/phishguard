import React from 'react';

// Medidor semicircular SVG que representa el score 0-100.
// 0-30 verde, 31-60 amarillo, 61-100 rojo.
const getColor = (score) => {
  if (score <= 30) return '#22c55e';
  if (score <= 60) return '#f59e0b';
  return '#ef4444';
};

const getLabel = (score) => {
  if (score <= 30) return 'Bajo riesgo';
  if (score <= 60) return 'Riesgo moderado';
  return 'Alto riesgo';
};

export default function ScoreGauge({ score = 0, size = 220 }) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const color = getColor(safeScore);

  // Geometría del semicírculo
  const stroke = 18;
  const radius = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  // Semicírculo desde 180º a 360º
  const circumference = Math.PI * radius;
  const offset = circumference - (safeScore / 100) * circumference;

  const isHighRisk = safeScore > 60;

  return (
    <div
      className={`flex flex-col items-center ${isHighRisk ? 'animate-pulse-slow' : ''}`}
      aria-label={`Score ${safeScore} de 100`}
    >
      <svg width={size} height={size / 2 + 12} viewBox={`0 0 ${size} ${size / 2 + 12}`}>
        {/* Pista de fondo */}
        <path
          d={`M ${stroke / 2} ${cy} A ${radius} ${radius} 0 0 1 ${size - stroke / 2} ${cy}`}
          fill="none"
          stroke="#1e293b"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        {/* Pista de progreso */}
        <path
          d={`M ${stroke / 2} ${cy} A ${radius} ${radius} 0 0 1 ${size - stroke / 2} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
        />
      </svg>
      <div className="-mt-10 text-center">
        <div className="text-5xl font-bold tabular-nums" style={{ color }}>
          {safeScore}
        </div>
        <div className="mt-1 text-xs uppercase tracking-widest text-slate-400">
          {getLabel(safeScore)}
        </div>
      </div>
    </div>
  );
}
