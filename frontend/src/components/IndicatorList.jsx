import React from 'react';

// Colores e iconos por severidad para mantener consistencia visual
const SEVERITY_STYLES = {
  high: {
    label: 'Alta',
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
    text: 'text-red-300',
    dot: 'bg-red-500',
  },
  medium: {
    label: 'Media',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/40',
    text: 'text-amber-300',
    dot: 'bg-amber-500',
  },
  low: {
    label: 'Baja',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/40',
    text: 'text-emerald-300',
    dot: 'bg-emerald-500',
  },
};

export default function IndicatorList({ indicators = [] }) {
  if (!indicators || indicators.length === 0) {
    return (
      <p className="text-sm text-slate-400">
        No se han detectado indicadores relevantes.
      </p>
    );
  }

  return (
    <ul className="space-y-2">
      {indicators.map((indicator, idx) => {
        const sev = SEVERITY_STYLES[indicator.severity] || SEVERITY_STYLES.low;
        return (
          <li
            key={`${indicator.name}-${idx}`}
            className={`rounded-lg border ${sev.border} ${sev.bg} p-3`}
          >
            <div className="flex items-start gap-3">
              <span className={`mt-1.5 inline-block h-2.5 w-2.5 rounded-full ${sev.dot}`} />
              <div className="flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-slate-100">{indicator.name}</span>
                  <span className={`text-xs font-semibold uppercase ${sev.text}`}>
                    {sev.label}
                  </span>
                </div>
                {indicator.detail && (
                  <p className="mt-1 text-sm text-slate-300">{indicator.detail}</p>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
