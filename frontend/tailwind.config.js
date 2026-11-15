/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0f1117',
        panel: '#161b27',
        border: '#1e2a3a',
        accent: '#3b82f6',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#22c55e',
        muted: '#6b7280',
      },
    },
  },
  plugins: [],
}
