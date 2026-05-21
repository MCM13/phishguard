import React, { useState } from 'react';
import { Link2 } from 'lucide-react';
import { analyzeUrl, friendlyError } from '../api.js';

export default function URLAnalyzer({ onResult, onAnalyzed, onLoading }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!url.trim()) {
      setError('Por favor, introduce una URL para analizar.');
      return;
    }
    setLoading(true);
    onLoading?.(true);
    setError(null);
    onResult && onResult(null);
    try {
      const data = await analyzeUrl(url.trim());
      onResult && onResult(data);
      onAnalyzed && onAnalyzed(data);
    } catch (err) {
      if (import.meta.env.DEV) console.error(err);
      setError(friendlyError(err));
    } finally {
      setLoading(false);
      onLoading?.(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <label className="block text-xs font-medium uppercase tracking-wider text-slate-400">
        URL sospechosa
      </label>
      <div className="relative">
        <Link2 className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://ejemplo-sospechoso.com/login"
          className="input-field pl-10 font-mono"
          disabled={loading}
        />
      </div>
      {error && (
        <p className="text-sm text-red-400" role="alert">
          {error}
        </p>
      )}
      <p className="text-xs text-slate-500">
        Combina extracción de features, VirusTotal, URLScan.io y Claude IA.
      </p>
      <button type="submit" disabled={loading} className="shine-btn w-full sm:w-auto">
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
            Analizando…
          </span>
        ) : (
          'Analizar URL'
        )}
      </button>
    </form>
  );
}
