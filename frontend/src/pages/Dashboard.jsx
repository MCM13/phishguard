import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  Brain,
  Gauge,
  Globe,
  Mail,
  ShieldCheck,
  Sparkles,
  Zap,
  ScanSearch,
} from 'lucide-react';
import URLAnalyzer from '../components/URLAnalyzer.jsx';
import EmailAnalyzer from '../components/EmailAnalyzer.jsx';
import ResultCard from '../components/ResultCard.jsx';
import { getStats } from '../api.js';

export default function Dashboard() {
  const [tab, setTab] = useState('url');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState(false);

  const loadStats = async () => {
    try {
      const data = await getStats();
      setStats(data);
      setStatsError(false);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      setStatsError(true);
    } finally {
      setStatsLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const handleResult = (data) => {
    setResult(data);
    if (data) loadStats();
  };

  const handleAnalyzeStart = () => {
    setLoading(true);
    setResult(null);
  };

  const detectionPct = () => {
    if (stats?.detection_rate === undefined) return undefined;
    const rate = stats.detection_rate;
    return `${Math.round(rate * (rate <= 1 ? 100 : 1))}%`;
  };

  const quotaLabel = () => {
    const daily = stats?.anthropic_quota?.daily;
    if (daily && !daily.unlimited && daily.limit != null) {
      return `${daily.remaining ?? 0}/${daily.limit}`;
    }
    return stats?.anthropic_quota ? '—' : undefined;
  };

  return (
    <div className="space-y-10">
      <section className="animate-fade-up relative text-center">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-300">
          <span className="inline-flex h-1.5 w-1.5 animate-pulse rounded-full bg-sky-400 shadow-[0_0_8px] shadow-sky-400" />
          Centro de operaciones · PhishGuard
        </div>
        <h1 className="font-display text-4xl font-bold leading-tight tracking-tight sm:text-5xl lg:text-6xl">
          <span className="text-gradient">Detecta phishing</span>
          <br />
          <span className="text-slate-100">antes de que te alcance.</span>
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-base text-slate-400">
          Analiza URLs y correos sospechosos con inteligencia artificial, threat intel y
          heurísticas avanzadas. Resultados en segundos.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          {[
            { icon: Brain, label: 'Claude IA' },
            { icon: ShieldCheck, label: 'VirusTotal' },
            { icon: Globe, label: 'URLScan.io' },
            { icon: Zap, label: 'Heurísticas' },
          ].map(({ icon: Icon, label }) => (
            <span
              key={label}
              className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-slate-300"
            >
              <Icon className="h-3.5 w-3.5 text-sky-400" />
              {label}
            </span>
          ))}
        </div>
      </section>

      {statsError && (
        <div className="animate-fade-up rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          No se pudieron cargar las estadísticas. ¿Está el backend en marcha?
        </div>
      )}

      <section className="animate-fade-up grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Total analizados" value={stats?.total_analyzed} icon={Activity} loading={statsLoading} />
        <StatCard
          label="Phishing detectados"
          value={stats?.phishing_detected}
          icon={AlertOctagon}
          loading={statsLoading}
          tone="phish"
        />
        <StatCard label="% detección" value={detectionPct()} icon={Gauge} loading={statsLoading} />
        <StatCard
          label="Score medio"
          value={stats?.avg_score !== undefined ? Math.round(stats.avg_score) : undefined}
          icon={Gauge}
          loading={statsLoading}
        />
        {quotaLabel() !== undefined && (
          <StatCard label="Cuota IA (hoy)" value={quotaLabel()} icon={Sparkles} loading={statsLoading} tone="brand" />
        )}
      </section>

      {stats?.anthropic_quota && !stats.anthropic_quota.can_call_claude && (
        <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          {stats.anthropic_quota.block_reason} Los análisis seguirán con reglas heurísticas locales.
        </p>
      )}

      <section className="grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <div className="glass glass-hover rounded-2xl p-6">
          <div className="mb-5">
            <h2 className="font-display text-lg font-semibold text-slate-100">Nuevo análisis</h2>
            <p className="text-xs text-slate-500">Selecciona el tipo de amenaza a inspeccionar.</p>
          </div>

          <div className="relative mb-5 grid grid-cols-2 rounded-xl border border-white/10 bg-slate-950/40 p-1">
            <span
              className="absolute inset-y-1 w-[calc(50%-4px)] rounded-lg bg-gradient-to-r from-sky-500/90 to-cyan-400/90 shadow-[0_0_20px_-4px] shadow-sky-500/60 transition-all duration-300"
              style={{ left: tab === 'url' ? 4 : 'calc(50% + 0px)' }}
            />
            <button
              type="button"
              onClick={() => {
                setTab('url');
                setResult(null);
              }}
              className={`relative z-10 inline-flex items-center justify-center gap-2 rounded-lg py-2 text-sm font-medium transition ${
                tab === 'url' ? 'text-slate-950' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="h-4 w-4" /> URL
            </button>
            <button
              type="button"
              onClick={() => {
                setTab('email');
                setResult(null);
              }}
              className={`relative z-10 inline-flex items-center justify-center gap-2 rounded-lg py-2 text-sm font-medium transition ${
                tab === 'email' ? 'text-slate-950' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="h-4 w-4" /> Email
            </button>
          </div>

          {tab === 'url' ? (
            <URLAnalyzer onResult={handleResult} onLoading={setLoading} />
          ) : (
            <EmailAnalyzer onResult={handleResult} onLoading={setLoading} />
          )}
        </div>

        <div className="min-h-[320px]">
          {loading && <ResultSkeleton />}
          {!loading && result && <ResultCard result={result} />}
          {!loading && !result && <EmptyResultPanel />}
        </div>
      </section>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, loading, tone }) {
  const toneBorder = {
    phish: 'hover:border-red-500/30',
    brand: 'hover:border-sky-500/30',
  };
  return (
    <div className={`glass glass-hover rounded-xl p-4 ${tone ? toneBorder[tone] || '' : ''}`}>
      <div className="mb-2 flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          {label}
        </span>
        <Icon className="h-4 w-4 text-slate-600" />
      </div>
      <div className="font-display text-2xl font-bold tabular-nums text-slate-100 sm:text-3xl">
        {loading ? <span className="skeleton inline-block h-8 w-16 rounded-lg" /> : (value ?? '—')}
      </div>
    </div>
  );
}

function ResultSkeleton() {
  return (
    <div className="glass rounded-2xl p-8">
      <div className="flex flex-col items-center gap-6">
        <div className="skeleton h-28 w-full max-w-[280px] rounded-full" />
        <div className="w-full space-y-3">
          <div className="skeleton h-6 w-40 rounded-lg" />
          <div className="skeleton h-4 w-full rounded-lg" />
          <div className="skeleton h-4 w-3/4 rounded-lg" />
          <div className="skeleton h-20 w-full rounded-xl" />
        </div>
      </div>
    </div>
  );
}

function EmptyResultPanel() {
  return (
    <div className="glass flex h-full min-h-[320px] flex-col items-center justify-center rounded-2xl border border-dashed border-white/10 p-8 text-center">
      <ScanSearch className="mb-4 h-12 w-12 text-slate-600" />
      <p className="font-display text-lg font-medium text-slate-400">Sin resultados aún</p>
      <p className="mt-2 max-w-xs text-sm text-slate-500">
        Introduce una URL o pega un email para ver el análisis aquí.
      </p>
    </div>
  );
}
