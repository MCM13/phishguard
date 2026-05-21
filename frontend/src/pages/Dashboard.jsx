import React, { useEffect, useState } from 'react';
import URLAnalyzer from '../components/URLAnalyzer.jsx';
import EmailAnalyzer from '../components/EmailAnalyzer.jsx';
import { getStats } from '../api.js';

const FEATURES = [
  { label: 'Claude IA', color: 'text-violet-300 border-violet-500/30 bg-violet-500/10' },
  { label: 'VirusTotal', color: 'text-sky-300 border-sky-500/30 bg-sky-500/10' },
  { label: 'URLScan.io', color: 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10' },
  { label: 'Heurísticas', color: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' },
];

export default function Dashboard() {
  const [tab, setTab] = useState('url');
  const [stats, setStats] = useState(null);
  const [statsError, setStatsError] = useState(false);

  const loadStats = async () => {
    try {
      const data = await getStats();
      setStats(data);
      setStatsError(false);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      setStatsError(true);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  return (
    <div className="space-y-10">
      <header className="animate-fade-up space-y-6 text-center md:text-left">
        <div className="inline-flex items-center gap-2 rounded-full border border-sky-500/25 bg-sky-500/10 px-3 py-1 text-xs font-medium text-sky-300">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
          </span>
          Motor de análisis activo
        </div>

        <div className="space-y-3">
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl">
            <span className="text-gradient-hero">Detector de phishing</span>
            <br />
            <span className="text-white">con inteligencia artificial</span>
          </h1>
          <p className="mx-auto max-w-2xl text-base text-slate-400 md:mx-0 md:text-lg">
            Analiza URLs y correos sospechosos en segundos. Combina IA, reputación
            global y señales locales en un único veredicto accionable.
          </p>
        </div>

        <div className="flex flex-wrap justify-center gap-2 md:justify-start">
          {FEATURES.map((f) => (
            <span
              key={f.label}
              className={`rounded-full border px-3 py-1 text-xs font-semibold ${f.color}`}
            >
              {f.label}
            </span>
          ))}
        </div>
      </header>

      <StatsPanel stats={stats} hasError={statsError} />

      <section className="glass-card animate-fade-up p-6 md:p-8" style={{ animationDelay: '0.1s' }}>
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Nuevo análisis</h2>
            <p className="text-sm text-slate-400">Elige el tipo de contenido a inspeccionar</p>
          </div>
          <div className="inline-flex rounded-xl border border-white/[0.08] bg-slate-950/80 p-1">
            <TabButton active={tab === 'url'} onClick={() => setTab('url')}>
              URL
            </TabButton>
            <TabButton active={tab === 'email'} onClick={() => setTab('email')}>
              Email
            </TabButton>
          </div>
        </div>

        {tab === 'url' ? (
          <URLAnalyzer onAnalyzed={loadStats} />
        ) : (
          <EmailAnalyzer onAnalyzed={loadStats} />
        )}
      </section>
    </div>
  );
}

function TabButton({ active, children, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg px-5 py-2.5 text-sm font-semibold transition ${
        active
          ? 'bg-gradient-to-r from-sky-500 to-cyan-400 text-slate-950 shadow-md shadow-sky-500/30'
          : 'text-slate-400 hover:text-white'
      }`}
    >
      {children}
    </button>
  );
}

function StatsPanel({ stats, hasError }) {
  if (hasError) {
    return (
      <div className="animate-fade-up rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
        No se pudieron cargar las estadísticas. ¿Está el backend en marcha?
      </div>
    );
  }

  const items = [
    { label: 'Total analizados', value: stats?.total_analyzed ?? '—', accent: 'sky' },
    { label: 'Phishing detectados', value: stats?.phishing_detected ?? '—', accent: 'red' },
    { label: '% detección', value: stats ? `${stats.detection_rate}%` : '—', accent: 'amber' },
    { label: 'Score medio', value: stats ? stats.avg_score : '—', accent: 'violet' },
  ];

  const accentRing = {
    sky: 'hover:border-sky-500/40 hover:shadow-sky-500/15',
    red: 'hover:border-red-500/40 hover:shadow-red-500/15',
    amber: 'hover:border-amber-500/40 hover:shadow-amber-500/15',
    violet: 'hover:border-violet-500/40 hover:shadow-violet-500/15',
  };

  const quota = stats?.anthropic_quota;
  const daily = quota?.daily;
  const quotaLabel =
    daily && !daily.unlimited && daily.limit != null
      ? `${daily.remaining ?? 0}/${daily.limit}`
      : null;

  return (
    <div className="animate-fade-up space-y-3" style={{ animationDelay: '0.05s' }}>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {items.map((item) => (
          <div
            key={item.label}
            className={`glass-card-hover p-4 ${accentRing[item.accent]}`}
          >
            <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              {item.label}
            </div>
            <div className="mt-2 text-3xl font-bold tabular-nums text-white">{item.value}</div>
          </div>
        ))}
        {quotaLabel && (
          <div
            className={`glass-card-hover p-4 ${
              quota?.can_call_claude
                ? 'border-sky-500/20 hover:border-sky-500/40'
                : 'border-amber-500/30 hover:border-amber-500/40'
            }`}
          >
            <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              Cuota IA (hoy)
            </div>
            <div className="mt-2 text-3xl font-bold tabular-nums text-white">{quotaLabel}</div>
            <div className="mt-1 text-xs text-slate-500">llamadas restantes</div>
          </div>
        )}
      </div>
      {quota && !quota.can_call_claude && (
        <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          {quota.block_reason} Los análisis seguirán con reglas heurísticas locales.
        </p>
      )}
    </div>
  );
}
