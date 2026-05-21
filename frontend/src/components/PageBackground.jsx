import React from 'react';

/** Fondo: rejilla técnica + orbes blur animados (threat-insight-suite). */
export default function PageBackground() {
  return (
    <div
      className="pointer-events-none fixed inset-0 -z-10 overflow-hidden"
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-[#020617]" />
      <div className="tech-grid absolute inset-0 opacity-60" />
      <div
        className="animate-orb absolute -left-32 -top-32 h-[40rem] w-[40rem] rounded-full opacity-[0.07] blur-3xl"
        style={{
          background: 'radial-gradient(circle, #0ea5e9 0%, transparent 60%)',
        }}
      />
      <div
        className="absolute right-0 top-1/3 h-[36rem] w-[36rem] rounded-full opacity-[0.06] blur-3xl"
        style={{
          background: 'radial-gradient(circle, #6366f1 0%, transparent 60%)',
          animation: 'orb 22s ease-in-out infinite reverse',
        }}
      />
      <div
        className="absolute bottom-0 left-1/3 h-[30rem] w-[30rem] rounded-full opacity-[0.04] blur-3xl"
        style={{
          background: 'radial-gradient(circle, #ef4444 0%, transparent 60%)',
          animation: 'orb 26s ease-in-out infinite',
        }}
      />
    </div>
  );
}
