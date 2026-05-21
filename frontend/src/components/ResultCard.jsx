import React from 'react';
import ScoreGauge from './ScoreGauge.jsx';
import IndicatorList from './IndicatorList.jsx';

// Mapa de estilos según el veredicto devuelto por la IA
const VERDICT_STYLES = {
  PHISHING: {
    label: 'PHISHING',
    pill: 'bg-red-500/15 text-red-300 border-red-500/40',
    border: 'border-red-500/30',
  },
  SOSPECHOSO: {
    label: 'SOSPECHOSO',
    pill: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    border: 'border-amber-500/30',
  },
  'LEGÍTIMO': {
    label: 'LEGÍTIMO',
    pill: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
    border: 'border-emerald-500/30',
  },
};

export default function ResultCard({ result }) {
  if (!result) return null;

  const verdictStyle = VERDICT_STYLES[result.verdict] || VERDICT_STYLES.SOSPECHOSO;
  const formattedDate = result.timestamp
    ? new Date(result.timestamp).toLocaleString('es-ES')
    : null;

  return (
    <div
      className={`animate-fade-up rounded-2xl border ${verdictStyle.border} bg-slate-900/70 p-6 shadow-xl shadow-black/30 backdrop-blur`}
    >
      <div className="flex flex-col items-center gap-6 md:flex-row md:items-start md:justify-between">
        <div className="w-full md:w-1/3">
          <ScoreGauge score={result.score} />
        </div>

        <div className="flex-1 space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold tracking-wider ${verdictStyle.pill}`}
            >
              {verdictStyle.label}
            </span>
            {result.url && (
              result.verdict === 'PHISHING' ? (
                // Para URLs marcadas como PHISHING NUNCA renderizamos un enlace
                // clicable. Se muestra como texto plano con etiqueta de aviso.
                <span
                  className="break-all rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-sm text-red-300 select-all"
                  title="Enlace deshabilitado por motivos de seguridad"
                  aria-label={`URL maliciosa (deshabilitada): ${result.url}`}
                >
                  <span className="mr-1 text-xs uppercase tracking-wider">[bloqueado]</span>
                  {result.url}
                </span>
              ) : (
                <a
                  href={result.url}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="break-all text-sm text-sky-400 hover:underline"
                >
                  {result.url}
                </a>
              )
            )}
          </div>

          <p className="text-slate-200">{result.ai_explanation}</p>

          {typeof result.virustotal_detections === 'number' && (
            <div className="text-xs text-slate-400">
              <span className="font-semibold text-slate-300">VirusTotal:</span>{' '}
              {result.virustotal_available === false ? (
                <span className="text-amber-300/90">
                  no configurado o sin datos para esta URL (añade VIRUSTOTAL_API_KEY en el
                  servidor).
                </span>
              ) : (
                <>
                  {result.virustotal_detections} de{' '}
                  {result.virustotal_total_engines ?? '?'} motores marcaron esta URL como
                  maliciosa o sospechosa.
                </>
              )}
            </div>
          )}

          {formattedDate && (
            <div className="text-xs text-slate-500">Analizado el {formattedDate}</div>
          )}
        </div>
      </div>

      <div className="mt-6">
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">
          Indicadores detectados
        </h3>
        <IndicatorList indicators={result.indicators} />
      </div>
    </div>
  );
}
