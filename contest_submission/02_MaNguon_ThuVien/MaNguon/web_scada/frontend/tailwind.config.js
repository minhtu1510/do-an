/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        plc: { on: "#22c55e", off: "#ef4444", warn: "#eab308", stale: "#6b7280" },
      },
    },
  },
  plugins: [],
};
