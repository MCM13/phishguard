import React, { useState } from 'react';
import { analyzeUrl, friendlyError } from '../api.js';
import ResultCard from './ResultCard.jsx';

// Formulario para analizar una URL sospechosa.
// Maneja el estado de carga, errores y muestra el resultado abajo.
export default function URLAnalyzer({ onAnalyzed }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!url.trim()) {
      setError('Por favor, introduce una URL para analizar.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzeUrl(url.trim());
      setResult(data);
      onAnalyzed && onAnalyzed(data);
    } catch (err) {
      // Sólo guardamos el error en consola en desarrollo; al usuario sólo le
      // mostramos un mensaje genérico/amigable sin trazas técnicas.
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
          URL sospechosa
        </label>
        <div className="flex flex-col gap-3 md:flex-row">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://ejemplo-sospechoso.com/login"
            className="input-glow flex-1 font-mono text-sm"
            disabled={loading}
          />
          <button type="submit" disabled={loading} className="btn-primary shrink-0">
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                Analizando…
              </span>
            ) : (
              'Analizar URL'
            )}
          </button>
        </div>
        {error && (
          <p className="text-sm text-red-400" role="alert">
            {error}
          </p>
        )}
        <p className="text-xs text-slate-500">
          El análisis combina extracción de features, VirusTotal, URLScan.io y Claude IA.
        </p>
      </form>

      {loading && <SkeletonResult />}
      {result && !loading && <ResultCard result={result} />}
    </div>
  );
}

// Esqueleto que se muestra mientras esperamos la respuesta del backend
function SkeletonResult() {
  return (
    <div className="glass-card overflow-hidden p-6">
      <div className="flex flex-col items-center gap-6 md:flex-row md:items-start md:justify-between">
        <div className="h-32 w-32 animate-shimmer rounded-full" />
        <div className="flex-1 space-y-3">
          <div className="h-6 w-32 animate-shimmer rounded-lg" />
          <div className="h-4 w-full animate-shimmer rounded-lg" />
          <div className="h-4 w-3/4 animate-shimmer rounded-lg" />
        </div>
      </div>
      <div className="mt-6 space-y-2">
        <div className="h-12 w-full animate-shimmer rounded-xl" />
        <div className="h-12 w-full animate-shimmer rounded-xl" />
      </div>
    </div>
  );
}
