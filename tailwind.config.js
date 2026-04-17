/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          50:  'rgb(var(--slate-50) / <alpha-value>)',
          100: 'rgb(var(--slate-100) / <alpha-value>)',
          200: 'rgb(var(--slate-200) / <alpha-value>)',
          300: 'rgb(var(--slate-300) / <alpha-value>)',
          400: 'rgb(var(--slate-400) / <alpha-value>)',
          500: 'rgb(var(--slate-500) / <alpha-value>)',
          600: 'rgb(var(--slate-600) / <alpha-value>)',
          700: 'rgb(var(--slate-700) / <alpha-value>)',
          800: 'rgb(var(--slate-800) / <alpha-value>)',
          900: 'rgb(var(--slate-900) / <alpha-value>)',
          950: 'rgb(var(--slate-950) / <alpha-value>)',
        },
        blue: {
          300: 'rgb(var(--blue-300) / <alpha-value>)',
          400: 'rgb(var(--blue-400) / <alpha-value>)',
        },
        emerald: {
          300: 'rgb(var(--emerald-300) / <alpha-value>)',
          400: 'rgb(var(--emerald-400) / <alpha-value>)',
        },
        amber: {
          300: 'rgb(var(--amber-300) / <alpha-value>)',
          400: 'rgb(var(--amber-400) / <alpha-value>)',
        },
        cyan: {
          300: 'rgb(var(--cyan-300) / <alpha-value>)',
          400: 'rgb(var(--cyan-400) / <alpha-value>)',
        },
        violet: {
          300: 'rgb(var(--violet-300) / <alpha-value>)',
          400: 'rgb(var(--violet-400) / <alpha-value>)',
        },
        red: {
          300: 'rgb(var(--red-300) / <alpha-value>)',
          400: 'rgb(var(--red-400) / <alpha-value>)',
        },
        green: {
          300: 'rgb(var(--green-300) / <alpha-value>)',
          400: 'rgb(var(--green-400) / <alpha-value>)',
        },
        yellow: {
          300: 'rgb(var(--yellow-300) / <alpha-value>)',
          400: 'rgb(var(--yellow-400) / <alpha-value>)',
        },
        orange: {
          300: 'rgb(var(--orange-300) / <alpha-value>)',
          400: 'rgb(var(--orange-400) / <alpha-value>)',
        },
        rose: {
          300: 'rgb(var(--rose-300) / <alpha-value>)',
          400: 'rgb(var(--rose-400) / <alpha-value>)',
        },
      },
    },
  },
  plugins: [],
}
