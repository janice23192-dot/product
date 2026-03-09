/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Palantir-inspired dark theme. Req 6.12
        primary: { DEFAULT: '#00d4ff', 50: '#e6fbff', 100: '#b3f3ff', 500: '#00d4ff', 700: '#00a3c7', 900: '#006b82' },
        surface: { DEFAULT: '#1a1a2e', 50: '#f5f5f9', 100: '#2d2d44', 200: '#16213e', 300: '#0f3460', 800: '#1a1a2e', 900: '#0d0d1a' },
        accent: { cyan: '#00d4ff', green: '#00ff88', red: '#ff4444', orange: '#ff8800', purple: '#8844ff' },
        severity: { critical: '#ff1744', high: '#ff6d00', medium: '#ffab00', low: '#00c853', info: '#2979ff' },
      },
      fontFamily: { mono: ['JetBrains Mono', 'Fira Code', 'monospace'] },
    },
  },
  plugins: [],
};
