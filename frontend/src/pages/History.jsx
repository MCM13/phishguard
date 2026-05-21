import React, { useEffect, useState } from 'react';
import HistoryTable from '../components/HistoryTable.jsx';
import { getHistory, friendlyError } from '../api.js';

// Página con el historial de análisis. Permite filtrar por veredicto.
export default function History() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [verdict, setVerdict] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getHistory({
        page,
        pageSize: 20,
        verdict: verdict || null,
      });
      setItems(data.items || []);
      setTotalPages(data.total_pages || 1);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [page, verdict]);

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Historial</h1>
          <p className="text-sm text-slate-400">
            Listado de todos los análisis realizados, ordenados del más reciente.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm text-slate-300">Filtrar:</label>
          <select
            value={verdict}
            onChange={(e) => {
              setVerdict(e.target.value);
              setPage(1);
            }}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
          >
            <option value="">Todos</option>
            <option value="PHISHING">PHISHING</option>
            <option value="SOSPECHOSO">SOSPECHOSO</option>
            <option value="LEGÍTIMO">LEGÍTIMO</option>
          </select>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      <HistoryTable items={items} loading={loading} />

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            type="button"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 disabled:opacity-40"
          >
            Anterior
          </button>
          <span className="text-sm text-slate-400">
            Página {page} de {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 disabled:opacity-40"
          >
            Siguiente
          </button>
        </div>
      )}
    </div>
  );
}
