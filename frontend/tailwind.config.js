/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#000000',
        panel: '#080808',
        border: '#1c1c1c',
        accent: '#3b82f6',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#22c55e',
        muted: '#71717a',
      },
    },
  },
  plugins: [],
}
