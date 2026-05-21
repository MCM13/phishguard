import React, { useState } from 'react';
import { Mail } from 'lucide-react';
import { analyzeEmail, friendlyError } from '../api.js';

export default function EmailAnalyzer({ onResult, onAnalyzed, onLoading }) {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (content.trim().length < 10) {
      setError('Pega al menos 10 caracteres del email para analizar.');
      return;
    }
    setLoading(true);
    onLoading?.(true);
    setError(null);
    onResult && onResult(null);
    try {
      const data = await analyzeEmail(content);
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
      <label className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-400">
        <Mail className="h-3.5 w-3.5" />
        Contenido del email
      </label>
      <textarea
        rows={10}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="Pega aquí el email completo o sólo el cuerpo del mensaje…"
        className="input-field resize-y font-mono text-sm"
        disabled={loading}
      />
      {error && (
        <p className="text-sm text-red-400" role="alert">
          {error}
        </p>
      )}
      <p className="text-xs text-slate-500">
        La IA analiza remitente, urgencia, palabras clave y enlaces incrustados.
      </p>
      <button type="submit" disabled={loading} className="shine-btn w-full sm:w-auto">
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
            Analizando…
          </span>
        ) : (
          'Analizar email'
        )}
      </button>
    </form>
  );
}
