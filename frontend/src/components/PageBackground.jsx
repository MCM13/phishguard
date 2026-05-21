import React from 'react';

/**
 * Capa decorativa de fondo: orbes animados + rejilla técnica.
 * No captura eventos del ratón (pointer-events-none).
 */
export default function PageBackground() {
  return (
    <div
      className="pointer-events-none fixed inset-0 -z-10 overflow-hidden"
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-[#020617]" />
      <div className="bg-grid absolute inset-0 opacity-[0.35]" />
      <div className="orb orb-cyan absolute -left-32 top-[-120px] h-[420px] w-[420px] rounded-full" />
      <div className="orb orb-violet absolute right-[-80px] top-[20%] h-[360px] w-[360px] rounded-full" />
      <div className="orb orb-red absolute bottom-[-100px] left-[30%] h-[320px] w-[320px] rounded-full" />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#020617]/40 to-[#020617]" />
    </div>
  );
}
