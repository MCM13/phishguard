import React from 'react';
import { Routes, Route, NavLink } from 'react-router-dom';
import PageBackground from './components/PageBackground.jsx';
import Dashboard from './pages/Dashboard.jsx';
import History from './pages/History.jsx';

export default function App() {
  return (
    <div className="relative min-h-screen text-slate-100">
      <PageBackground />

      <header className="sticky top-0 z-50 border-b border-white/[0.06] bg-slate-950/70 backdrop-blur-xl">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <NavLink
            to="/"
            className="group flex items-center gap-3 transition hover:opacity-90"
          >
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 shadow-lg shadow-sky-500/20 transition group-hover:border-sky-400/50 group-hover:shadow-sky-500/30">
              <ShieldLogo />
            </span>
            <div>
              <span className="block text-lg font-bold tracking-tight text-white">
                PhishGuard
              </span>
              <span className="text-[10px] font-medium uppercase tracking-[0.2em] text-sky-400/80">
                Threat Intel
              </span>
            </div>
          </NavLink>

          <nav className="flex items-center gap-1 rounded-xl border border-white/[0.06] bg-slate-900/50 p-1 backdrop-blur">
            <NavItem to="/">Analizar</NavItem>
            <NavItem to="/history">Historial</NavItem>
          </nav>
        </div>
      </header>

      <main className="relative mx-auto max-w-6xl px-4 py-8 md:py-12">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>

      <footer className="relative border-t border-white/[0.04] py-8 text-center text-xs text-slate-500">
        PhishGuard · Análisis de phishing con IA · Resultados orientativos
      </footer>
    </div>
  );
}

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        `rounded-lg px-4 py-2 text-sm font-medium transition ${
          isActive
            ? 'bg-gradient-to-r from-sky-500/20 to-cyan-500/10 text-sky-300 shadow-inner'
            : 'text-slate-400 hover:bg-slate-800/60 hover:text-white'
        }`
      }
    >
      {children}
    </NavLink>
  );
}

function ShieldLogo() {
  return (
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-sky-400"
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}
