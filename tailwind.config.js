/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        void: '#05080c',
        terminal: {
          panel: '#0b1017',
          surface: '#0e141e',
          border: '#1e293b',
          muted: '#334155',
        },
        tactical: {
          cyan: '#00f0ff',
          emerald: '#10b981',
          crimson: '#ef4444',
          amber: '#f59e0b',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', '"Liberation Mono"', '"Courier New"', 'monospace'],
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: '1', filter: 'drop-shadow(0 0 6px rgba(0, 240, 255, 0.8))' },
          '50%': { opacity: '0.4', filter: 'drop-shadow(0 0 2px rgba(0, 240, 255, 0.2))' },
        },
        beaconGreen: {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 8px #10b981, 0 0 16px rgba(16, 185, 129, 0.4)' },
          '50%': { opacity: '0.3', boxShadow: '0 0 2px #10b981' },
        },
        beaconAmber: {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 8px #f59e0b, 0 0 16px rgba(245, 158, 11, 0.4)' },
          '50%': { opacity: '0.3', boxShadow: '0 0 2px #f59e0b' },
        },
        beaconRed: {
          '0%, 100%': { opacity: '1', boxShadow: '0 0 8px #ef4444, 0 0 16px rgba(239, 68, 68, 0.4)' },
          '50%': { opacity: '0.3', boxShadow: '0 0 2px #ef4444' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'beacon-green': 'beaconGreen 1.5s ease-in-out infinite',
        'beacon-amber': 'beaconAmber 1.2s ease-in-out infinite',
        'beacon-red': 'beaconRed 0.8s ease-in-out infinite',
        'scanline': 'scanline 8s linear infinite',
      },
    },
  },
  plugins: [],
};
