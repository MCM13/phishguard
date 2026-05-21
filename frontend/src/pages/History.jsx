import React, { useEffect, useState } from 'react';
import { History as HistoryIcon } from 'lucide-react';
import HistoryTable from '../components/HistoryTable.jsx';
import { getHistory, friendlyError } from '../api.js';

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

  const handleVerdictChange = (value) => {
    setVerdict(value);
    setPage(1);
  };

  return (
    <div className="animate-fade-up space-y-8">
      <header className="text-center sm:text-left">
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-400">
          <HistoryIcon className="h-3.5 w-3.5 text-sky-400" />
          Registro de análisis
        </div>
        <h1 className="font-display text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
          Historial de análisis
        </h1>
        <p className="mt-2 text-slate-400">
          Registro completo ordenado del más reciente al más antiguo.
        </p>
      </header>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      <HistoryTable
        items={items}
        loading={loading}
        verdict={verdict}
        onVerdictChange={handleVerdictChange}
        page={page}
        totalPages={totalPages}
        onPageChange={setPage}
        totalCount={items.length}
      />
    </div>
  );
}
