import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Shield,
  Sparkles,
  Lock,
  Clock,
} from 'lucide-react';
import ScoreGauge from './ScoreGauge.jsx';
import IndicatorList from './IndicatorList.jsx';

const VERDICT_META = {
  PHISHING: {
    icon: ShieldAlert,
    label: 'Phishing detectado',
    glow: 'shadow-[0_0_60px_-12px_rgba(239,68,68,0.55)] border-red-500/40',
    pill: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/40',
    accent: 'from-red-500/20 to-transparent',
  },
  SOSPECHOSO: {
    icon: ShieldQuestion,
    label: 'Sospechoso',
    glow: 'shadow-[0_0_60px_-12px_rgba(245,158,11,0.5)] border-amber-500/40',
    pill: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/40',
    accent: 'from-amber-500/20 to-transparent',
  },
  'LEGÍTIMO': {
    icon: ShieldCheck,
    label: 'Legítimo',
    glow: 'shadow-[0_0_60px_-12px_rgba(16,185,129,0.5)] border-emerald-500/40',
    pill: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/40',
    accent: 'from-emerald-500/20 to-transparent',
  },
};

export default function ResultCard({ result }) {
  if (!result) return null;

  const meta = VERDICT_META[result.verdict] || VERDICT_META.SOSPECHOSO;
  const Icon = meta.icon;
  const isPhish = result.verdict === 'PHISHING';
  const target = result.url || '';

  return (
    <div className={`glass relative overflow-hidden rounded-2xl border ${meta.glow} animate-fade-up`}>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/30 to-transparent" />
      <div
        className={`pointer-events-none absolute -top-24 left-1/2 h-48 w-[120%] -translate-x-1/2 bg-gradient-to-b ${meta.accent} blur-2xl`}
      />

      <div className="relative grid gap-6 p-6 md:grid-cols-[auto_1fr] md:p-8">
        <div className="flex justify-center md:justify-start">
          <ScoreGauge score={result.score} verdict={result.verdict} />
        </div>

        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wider ${meta.pill}`}
            >
              <Icon className="h-3.5 w-3.5" />
              {meta.label}
            </span>
            {result.timestamp && (
              <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
                <Clock className="h-3 w-3" />
                {new Date(result.timestamp).toLocaleString('es-ES')}
              </span>
            )}
          </div>

          {target && (
            <div className="rounded-xl border border-white/5 bg-slate-950/40 p-3">
              <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">
                Objetivo analizado
              </div>
              {isPhish ? (
                <div className="flex flex-wrap items-center gap-2">
                  <code className="break-all font-mono text-sm text-red-300/90 line-through decoration-red-500/40">
                    {target}
                  </code>
                  <span className="inline-flex items-center gap-1 rounded-md bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold text-red-300 ring-1 ring-red-500/30">
                    <Lock className="h-3 w-3" /> bloqueado
                  </span>
                </div>
              ) : (
                <a
                  href={target}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="break-all font-mono text-sm text-sky-300 hover:text-sky-200 hover:underline"
                >
                  {target}
                </a>
              )}
            </div>
          )}

          {result.ai_explanation && (
            <div className="rounded-xl border border-sky-500/20 bg-sky-500/[0.04] p-4">
              <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-sky-300">
                <Sparkles className="h-3.5 w-3.5" /> Análisis de Claude IA
              </div>
              <p className="text-sm leading-relaxed text-slate-200">{result.ai_explanation}</p>
            </div>
          )}

          {(result.virustotal_available !== false ||
            typeof result.virustotal_detections === 'number') && (
            <div className="flex flex-wrap items-center gap-3 rounded-xl border border-white/5 bg-white/[0.02] p-3">
              <Shield className="h-5 w-5 shrink-0 text-cyan-400" />
              <div className="text-sm text-slate-300">
                <span className="font-semibold text-slate-100">VirusTotal: </span>
                {result.virustotal_available === false ? (
                  <span className="text-amber-300/90">
                    no configurado o sin datos (añade VIRUSTOTAL_API_KEY en el servidor).
                  </span>
                ) : (
                  <>
                    {result.virustotal_detections} de{' '}
                    {result.virustotal_total_engines ?? '?'} motores marcaron esta URL como
                    maliciosa o sospechosa.
                  </>
                )}
              </div>
            </div>
          )}

          <div>
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Indicadores ({result.indicators?.length || 0})
            </h4>
            <IndicatorList indicators={result.indicators} />
          </div>
        </div>
      </div>
    </div>
  );
}
