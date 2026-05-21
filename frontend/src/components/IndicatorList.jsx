import React from 'react';
import { AlertTriangle, AlertCircle, Info } from 'lucide-react';

const SEVERITY_STYLES = {
  high: {
    label: 'Alta',
    icon: AlertTriangle,
    cls: 'text-red-400',
    ring: 'ring-red-500/30 bg-red-500/5',
  },
  medium: {
    label: 'Media',
    icon: AlertCircle,
    cls: 'text-amber-400',
    ring: 'ring-amber-500/30 bg-amber-500/5',
  },
  low: {
    label: 'Baja',
    icon: Info,
    cls: 'text-sky-400',
    ring: 'ring-sky-500/30 bg-sky-500/5',
  },
};

export default function IndicatorList({ indicators = [] }) {
  if (!indicators || indicators.length === 0) {
    return (
      <p className="text-sm text-slate-500">No se han detectado indicadores relevantes.</p>
    );
  }

  return (
    <ul className="space-y-2">
      {indicators.map((indicator, idx) => {
        const sev = SEVERITY_STYLES[indicator.severity] || SEVERITY_STYLES.low;
        const Icon = sev.icon;
        return (
          <li
            key={`${indicator.name}-${idx}`}
            className={`flex items-start gap-3 rounded-lg p-3 ring-1 ${sev.ring}`}
            style={{ animation: `fadeUp 0.4s ${idx * 60}ms backwards ease-out` }}
          >
            <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${sev.cls}`} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-slate-100">{indicator.name}</span>
                <span className={`text-[10px] font-semibold uppercase tracking-wider ${sev.cls}`}>
                  {sev.label}
                </span>
              </div>
              {indicator.detail && (
                <p className="mt-0.5 text-sm leading-relaxed text-slate-300">{indicator.detail}</p>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
