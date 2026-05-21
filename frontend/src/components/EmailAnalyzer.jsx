import React, { useState } from 'react';
import { analyzeEmail, friendlyError } from '../api.js';
import ResultCard from './ResultCard.jsx';

// Formulario para analizar el texto de un email sospechoso.
// Pega el email completo (con cabeceras) o sólo el cuerpo.
export default function EmailAnalyzer({ onAnalyzed }) {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (content.trim().length < 10) {
      setError('Pega al menos 10 caracteres del email para analizar.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzeEmail(content);
      setResult(data);
      onAnalyzed && onAnalyzed(data);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      setError(friendlyError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="space-y-3">
        <label className="block text-sm font-medium text-slate-300">
          Contenido del email
        </label>
        <textarea
          rows={10}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Pega aquí el email completo o sólo el cuerpo del mensaje…"
          className="w-full resize-y rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/30"
          disabled={loading}
        />
        <div className="flex flex-col items-stretch gap-3 md:flex-row md:items-center md:justify-between">
          <p className="text-xs text-slate-500">
            La IA analiza remitente, urgencia, palabras clave y enlaces incrustados.
          </p>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center rounded-lg bg-sky-500 px-6 py-3 font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                Analizando…
              </span>
            ) : (
              'Analizar email'
            )}
          </button>
        </div>
        {error && (
          <p className="text-sm text-red-400" role="alert">
            {error}
          </p>
        )}
      </form>

      {result && !loading && <ResultCard result={result} />}
    </div>
  );
}
