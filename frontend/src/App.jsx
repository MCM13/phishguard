import React from 'react';
import { Routes, Route, NavLink } from 'react-router-dom';
import { Shield } from 'lucide-react';
import PageBackground from './components/PageBackground.jsx';
import Dashboard from './pages/Dashboard.jsx';
import History from './pages/History.jsx';

export default function App() {
  return (
    <div className="relative min-h-screen text-slate-100">
      <PageBackground />

      <header className="sticky top-0 z-40 border-b border-white/5 bg-slate-950/60 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
          <NavLink to="/" className="group flex items-center gap-2.5">
            <div className="relative grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-sky-400 to-indigo-500 shadow-[0_0_20px_-4px] shadow-sky-500/60 transition group-hover:shadow-sky-400/80">
              <Shield className="h-5 w-5 text-slate-950" strokeWidth={2.5} />
            </div>
            <div className="flex flex-col leading-none">
              <span className="font-display text-base font-bold tracking-tight text-slate-100">
                PhishGuard
              </span>
              <span className="text-[10px] uppercase tracking-[0.18em] text-slate-500">
                Threat intel · AI
              </span>
            </div>
          </NavLink>

          <nav className="flex items-center gap-1 rounded-full border border-white/10 bg-white/[0.03] p-1">
            <NavItem to="/">Analizar</NavItem>
            <NavItem to="/history">Historial</NavItem>
          </nav>

          <div className="hidden items-center gap-2 sm:flex">
            <span className="inline-flex h-2 w-2 animate-pulse rounded-full bg-emerald-400 shadow-[0_0_8px] shadow-emerald-400" />
            <span className="text-xs text-slate-400">Sistema operativo</span>
          </div>
        </div>
      </header>

      <main className="relative mx-auto max-w-7xl px-4 pb-24 pt-8 sm:px-6 md:pt-10">
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
        `relative rounded-full px-4 py-1.5 text-sm font-medium transition ${
          isActive ? 'text-slate-950' : 'text-slate-300 hover:text-white'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && (
            <span className="absolute inset-0 rounded-full bg-gradient-to-r from-sky-400 to-cyan-300 shadow-[0_0_20px_-4px] shadow-sky-400/70" />
          )}
          <span className="relative">{children}</span>
        </>
      )}
    </NavLink>
  );
}
