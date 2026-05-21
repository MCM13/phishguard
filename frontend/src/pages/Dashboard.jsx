import React, { useEffect, useState } from 'react';
import URLAnalyzer from '../components/URLAnalyzer.jsx';
import EmailAnalyzer from '../components/EmailAnalyzer.jsx';
import { getStats } from '../api.js';

// Página principal con dos tabs (URL / Email) y panel de estadísticas globales
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
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight text-white md:text-4xl">
          Detector de phishing con IA
        </h1>
        <p className="max-w-2xl text-slate-400">
          Pega una URL o el contenido de un email sospechoso para obtener un
          análisis instantáneo combinando inteligencia artificial, VirusTotal y
          URLScan.io.
        </p>
      </header>

      <StatsPanel stats={stats} hasError={statsError} />

      <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6">
        <div className="mb-6 inline-flex rounded-lg border border-slate-800 bg-slate-950 p-1">
          <TabButton active={tab === 'url'} onClick={() => setTab('url')}>
            Analizar URL
          </TabButton>
          <TabButton active={tab === 'email'} onClick={() => setTab('email')}>
            Analizar email
          </TabButton>
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
      className={`rounded-md px-4 py-2 text-sm font-semibold transition ${
        active
          ? 'bg-sky-500 text-slate-950'
          : 'text-slate-300 hover:text-white'
      }`}
    >
      {children}
    </button>
  );
}

function StatsPanel({ stats, hasError }) {
  if (hasError) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
        No se pudieron cargar las estadísticas. ¿Está el backend en marcha?
      </div>
    );
  }

  const items = [
    {
      label: 'Total analizados',
      value: stats?.total_analyzed ?? '—',
    },
    {
      label: 'Phishing detectados',
      value: stats?.phishing_detected ?? '—',
    },
    {
      label: '% de detección',
      value: stats ? `${stats.detection_rate}%` : '—',
    },
    {
      label: 'Score medio',
      value: stats ? stats.avg_score : '—',
    },
  ];

  const quota = stats?.anthropic_quota;
  const daily = quota?.daily;
  const quotaLabel =
    daily && !daily.unlimited && daily.limit != null
      ? `${daily.remaining ?? 0}/${daily.limit}`
      : null;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {items.map((item) => (
          <div
            key={item.label}
            className="rounded-xl border border-slate-800 bg-slate-900/40 p-4"
          >
            <div className="text-xs uppercase tracking-wider text-slate-400">
              {item.label}
            </div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-white">
              {item.value}
            </div>
          </div>
        ))}
        {quotaLabel && (
          <div
            className={`rounded-xl border p-4 ${
              quota?.can_call_claude
                ? 'border-sky-500/30 bg-sky-500/10'
                : 'border-amber-500/40 bg-amber-500/10'
            }`}
          >
            <div className="text-xs uppercase tracking-wider text-slate-400">
              Cuota IA (hoy)
            </div>
            <div className="mt-2 text-2xl font-bold tabular-nums text-white">
              {quotaLabel}
            </div>
            <div className="mt-1 text-xs text-slate-400">llamadas restantes</div>
          </div>
        )}
      </div>
      {quota && !quota.can_call_claude && (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
          {quota.block_reason} Los análisis seguirán con reglas heurísticas locales.
        </p>
      )}
    </div>
  );
}
