/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'Inter', 'system-ui', 'sans-serif'],
        display: ['"Space Grotesk"', '"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
      },
      colors: {
        phish: '#ef4444',
        suspect: '#f59e0b',
        legit: '#10b981',
        brand: {
          DEFAULT: '#38bdf8',
          2: '#22d3ee',
        },
      },
      animation: {
        orb: 'orb 18s ease-in-out infinite',
        'gradient-shift': 'gradientShift 8s ease infinite',
        shimmer: 'shimmer 1.6s linear infinite',
        'fade-up': 'fadeUp 0.5s ease-out both',
      },
      keyframes: {
        orb: {
          '0%, 100%': { transform: 'translate(0, 0) scale(1)' },
          '33%': { transform: 'translate(40px, -30px) scale(1.1)' },
          '66%': { transform: 'translate(-30px, 40px) scale(0.95)' },
        },
        gradientShift: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        fadeUp: {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
