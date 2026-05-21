import React from 'react';

const VERDICT_PILL = {
  PHISHING: 'bg-red-500/15 text-red-300 border-red-500/40',
  SOSPECHOSO: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  'LEGÍTIMO': 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
};

// Tabla con el historial de análisis. Recibe la lista ya filtrada/paginada.
export default function HistoryTable({ items = [], loading = false }) {
  if (loading) {
    return (
      <div className="glass-card p-8 text-center text-slate-400">
        <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
        <span className="ml-2">Cargando historial…</span>
      </div>
    );
  }

  if (!items.length) {
    return (
      <div className="glass-card p-8 text-center text-slate-400">
        Aún no hay análisis registrados.
      </div>
    );
  }

  return (
    <div className="glass-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-sm">
          <thead className="bg-slate-900/80 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">Fecha</th>
              <th className="px-4 py-3">Tipo</th>
              <th className="px-4 py-3">Entrada</th>
              <th className="px-4 py-3 text-center">Score</th>
              <th className="px-4 py-3">Veredicto</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.06]">
            {items.map((item) => {
              const pill = VERDICT_PILL[item.verdict] || VERDICT_PILL.SOSPECHOSO;
              const date = item.timestamp ? new Date(item.timestamp).toLocaleString('es-ES') : '';
              const inputText = (item.url || item.input || '').slice(0, 80);
              return (
                <tr
                  key={item.id}
                  className="transition hover:bg-sky-500/[0.04]"
                >
                  <td className="whitespace-nowrap px-4 py-3 text-slate-300">{date}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                    {item.type === 'url' ? 'URL' : 'Email'}
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    <span className="break-all" title={item.url || item.input}>
                      {inputText}
                      {(item.url || item.input || '').length > 80 ? '…' : ''}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-center font-semibold tabular-nums text-slate-100">
                    {item.score}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-semibold ${pill}`}>
                      {item.verdict}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
