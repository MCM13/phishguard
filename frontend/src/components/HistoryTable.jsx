import React from 'react';
import { Filter, Lock, ChevronLeft, ChevronRight } from 'lucide-react';

const VERDICT_PILL = {
  PHISHING: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
  SOSPECHOSO: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
  'LEGÍTIMO': 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
};

const FILTER_OPTIONS = [
  { value: '', label: 'Todos' },
  { value: 'PHISHING', label: 'PHISHING' },
  { value: 'SOSPECHOSO', label: 'SOSPECHOSO' },
  { value: 'LEGÍTIMO', label: 'LEGÍTIMO' },
];

export default function HistoryTable({
  items = [],
  loading = false,
  verdict = '',
  onVerdictChange,
  page = 1,
  totalPages = 1,
  onPageChange,
  totalCount,
}) {
  return (
    <div className="glass overflow-hidden rounded-2xl">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 p-4">
        <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
          <Filter className="h-4 w-4 shrink-0" />
          <span>Filtrar:</span>
          {FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.value || 'all'}
              type="button"
              onClick={() => onVerdictChange?.(opt.value)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                verdict === opt.value
                  ? 'bg-sky-400 text-slate-950'
                  : 'border border-white/10 text-slate-300 hover:border-sky-400/40 hover:text-sky-300'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        {totalCount != null && (
          <span className="text-xs text-slate-500">{totalCount} en esta página</span>
        )}
      </div>

      {loading ? (
        <div className="p-12 text-center">
          <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <p className="mt-3 text-sm text-slate-500">Cargando historial…</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/5 text-left text-[10px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-semibold">Veredicto</th>
                <th className="px-4 py-3 font-semibold">Tipo</th>
                <th className="px-4 py-3 font-semibold">Entrada</th>
                <th className="px-4 py-3 font-semibold text-center">Score</th>
                <th className="px-4 py-3 font-semibold">Fecha</th>
              </tr>
            </thead>
            <tbody>
              {!items.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                    Aún no hay análisis registrados.
                  </td>
                </tr>
              )}
              {items.map((item) => {
                const pill = VERDICT_PILL[item.verdict] || VERDICT_PILL.SOSPECHOSO;
                const isPhish = item.verdict === 'PHISHING';
                const inputText = (item.url || item.input || '').slice(0, 80);
                const fullText = item.url || item.input || '';
                const date = item.timestamp
                  ? new Date(item.timestamp).toLocaleString('es-ES')
                  : '';
                return (
                  <tr
                    key={item.id}
                    className="border-b border-white/5 transition hover:bg-white/[0.03]"
                  >
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${pill}`}
                      >
                        {item.verdict}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                      {item.type === 'url' ? 'URL' : 'Email'}
                    </td>
                    <td className="max-w-[320px] px-4 py-3 font-mono text-xs sm:max-w-[420px]">
                      {isPhish ? (
                        <span
                          className="flex items-center gap-2 text-red-300/80 line-through decoration-red-500/40"
                          title={fullText}
                        >
                          <Lock className="h-3 w-3 shrink-0" />
                          <span className="truncate">{inputText}</span>
                        </span>
                      ) : (
                        <span className="block truncate text-slate-300" title={fullText}>
                          {inputText}
                          {fullText.length > 80 ? '…' : ''}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-center font-display font-semibold tabular-nums text-slate-100">
                      {item.score}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                      {date}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && !loading && (
        <div className="flex items-center justify-between border-t border-white/5 px-4 py-3">
          <button
            type="button"
            onClick={() => onPageChange?.(Math.max(1, page - 1))}
            disabled={page <= 1}
            className="inline-flex items-center gap-1 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300 transition hover:border-sky-400/40 disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" /> Anterior
          </button>
          <span className="text-xs text-slate-500">
            Página {page} de {totalPages}
          </span>
          <button
            type="button"
            onClick={() => onPageChange?.(Math.min(totalPages, page + 1))}
            disabled={page >= totalPages}
            className="inline-flex items-center gap-1 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300 transition hover:border-sky-400/40 disabled:opacity-40"
          >
            Siguiente <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
