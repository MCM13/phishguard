/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Colores corporativos: tonos oscuros + acentos por severidad
        brand: {
          DEFAULT: '#0f172a',
          accent: '#38bdf8',
        },
        verdict: {
          safe: '#22c55e',
          warn: '#f59e0b',
          danger: '#ef4444',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
