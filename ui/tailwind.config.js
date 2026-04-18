/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["../templates/ui/**/*.html"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        hearth: {
          50: "#eef2fe",
          100: "#dfe7fd",
          200: "#c5d2fb",
          300: "#a1b6f8",
          400: "#6490fa",
          500: "#3b6cf5",
          600: "#2b52e0",
          700: "#2341c4",
          800: "#22369f",
          900: "#21327e",
          950: "#181f4d",
        },
      },
      fontFamily: {
        sans: [
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
      },
      boxShadow: {
        card: "0 1px 3px 0 rgb(0 0 0 / 0.04), 0 1px 2px -1px rgb(0 0 0 / 0.04)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(-4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "toast-in": {
          from: { opacity: "0", transform: "translateX(100%)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "toast-out": {
          from: { opacity: "1", transform: "translateX(0)" },
          to: { opacity: "0", transform: "translateX(100%)" },
        },
        spinner: {
          to: { transform: "rotate(360deg)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.2s ease-out",
        "toast-in": "toast-in 0.3s ease-out",
        "toast-out": "toast-out 0.3s ease-in forwards",
        spinner: "spinner 0.6s linear infinite",
      },
    },
  },
  plugins: [],
};
