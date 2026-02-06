/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        // Warm brown-tinted zinc override for cozy feel
        zinc: {
          50:  '#faf8f4',
          100: '#f0ebe4',
          200: '#e0d8ce',
          300: '#cdc2b4',
          400: '#a39587',
          500: '#847668',
          600: '#655850',
          700: '#4a403a',
          800: '#352e29',
          900: '#28231e',
          950: '#1e1a16',
        },
        dark: {
          50:  '#faf8f4',
          100: '#f0ebe4',
          200: '#e0d8ce',
          300: '#cdc2b4',
          400: '#a39587',
          500: '#847668',
          600: '#655850',
          700: '#4a403a',
          800: '#352e29',
          900: '#28231e',
          950: '#1e1a16',
        },
        primary: {
          50: '#faf7f4',
          100: '#f0e8de',
          200: '#e0d0bb',
          300: '#c9ad8a',
          400: '#b5915f',
          500: '#b07d4f',
          600: '#946639',
          700: '#7a522e',
          800: '#634225',
          900: '#52361f',
        },
        accent: {
          50: '#faf7f4',
          100: '#f0e8de',
          200: '#e0d0bb',
          300: '#c9ad8a',
          400: '#b5915f',
          500: '#b07d4f',
          600: '#946639',
          700: '#7a522e',
          800: '#634225',
          900: '#52361f',
        },
        cyan: {
          400: '#d4a84b',
          500: '#c49a3d',
          600: '#a88232',
        },
        danger: {
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
        },
        warning: {
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
        },
      },
      boxShadow: {
        'glow-green': '0 0 20px rgba(176, 125, 79, 0.15), 0 0 40px rgba(176, 125, 79, 0.05)',
        'glow-green-sm': '0 0 10px rgba(176, 125, 79, 0.1)',
        'glow-green-lg': '0 0 30px rgba(176, 125, 79, 0.2), 0 0 60px rgba(176, 125, 79, 0.08)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.15), 0 0 40px rgba(239, 68, 68, 0.05)',
        'glow-red-sm': '0 0 10px rgba(239, 68, 68, 0.1)',
        'glow-cyan': '0 0 20px rgba(212, 168, 75, 0.15), 0 0 40px rgba(212, 168, 75, 0.05)',
        'glow-cyan-sm': '0 0 10px rgba(212, 168, 75, 0.1)',
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'fade-in': 'fade-in 0.3s ease-out',
        'modal-in': 'modal-in 0.2s ease-out',
        'overlay-in': 'overlay-in 0.2s ease-out',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 8px rgba(176, 125, 79, 0.2)' },
          '50%': { boxShadow: '0 0 20px rgba(176, 125, 79, 0.4), 0 0 40px rgba(176, 125, 79, 0.1)' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'modal-in': {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        'overlay-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
