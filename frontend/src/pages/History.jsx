import React, { useEffect, useState } from 'react';
import { History as HistoryIcon, KeyRound, LogOut } from 'lucide-react';
import HistoryTable from '../components/HistoryTable.jsx';
import { getHistory, friendlyError, hasAdminToken, setAdminToken } from '../api.js';

export default function History() {
  const [authorized, setAuthorized] = useState(hasAdminToken());
  const [tokenInput, setTokenInput] = useState('');
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [verdict, setVerdict] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

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
      setTotal(data.total || 0);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      if (err?.response?.status === 401) {
        setAdminToken('');
        setAuthorized(false);
        setItems([]);
      }
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (authorized) load();
  }, [page, verdict, authorized]);

  const handleVerdictChange = (value) => {
    setVerdict(value);
    setPage(1);
  };

  const handleTokenSubmit = (event) => {
    event.preventDefault();
    if (!tokenInput.trim()) {
      setError('Introduce el token de administrador.');
      return;
    }
    setAdminToken(tokenInput);
    setTokenInput('');
    setPage(1);
    setAuthorized(true);
  };

  const handleLogout = () => {
    setAdminToken('');
    setAuthorized(false);
    setItems([]);
    setError(null);
  };

  return (
    <div className="animate-fade-up space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4 text-center sm:text-left">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-slate-400">
            <HistoryIcon className="h-3.5 w-3.5 text-sky-400" />
            Registro de análisis
          </div>
          <h1 className="font-display text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
            Historial de análisis
          </h1>
          <p className="mt-2 text-slate-400">
            Acceso restringido. Por privacidad sólo se conserva el tipo, el veredicto, el score,
            la fecha, el dominio y una huella del contenido.
          </p>
        </div>
        {authorized && (
          <button
            type="button"
            onClick={handleLogout}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300 transition hover:border-sky-400/40"
          >
            <LogOut className="h-3.5 w-3.5" /> Cerrar acceso
          </button>
        )}
      </header>

      {error && (
        <div role="alert" className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {!authorized ? (
        <form onSubmit={handleTokenSubmit} className="glass mx-auto max-w-md space-y-4 rounded-2xl p-6">
          <div className="flex items-center gap-2 text-slate-200">
            <KeyRound className="h-4 w-4 text-sky-400" />
            <h2 className="font-display text-lg font-semibold">Token de administrador</h2>
          </div>
          <p className="text-xs text-slate-500">
            Es el valor de <code className="font-mono">ADMIN_TOKEN</code> configurado en el backend.
            Se guarda sólo en memoria hasta que recargues la página.
          </p>
          <input
            type="password"
            autoComplete="off"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            className="input-field font-mono"
            placeholder="ADMIN_TOKEN"
            aria-label="Token de administrador"
          />
          <button type="submit" className="shine-btn w-full">
            Ver historial
          </button>
        </form>
      ) : (
        <HistoryTable
          items={items}
          loading={loading}
          verdict={verdict}
          onVerdictChange={handleVerdictChange}
          page={page}
          totalPages={totalPages}
          onPageChange={setPage}
          totalCount={total}
        />
      )}
    </div>
  );
}
