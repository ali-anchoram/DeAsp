/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:      "#0d1117",
        panel:   "#161b22",
        border:  "#30363d",
        muted:   "#8b949e",
        sys:     "#6e7681",
        "sys-bg": "#1a1d23",
        evt:     "#58a6ff",
        "evt-bg": "#0d2244",
        ajax:    "#bc8cff",
        "ajax-bg": "#1c1440",
        usr:     "#56d364",
        "usr-bg": "#0f2a16",
        warn:    "#f0883e",
        "warn-bg": "#2d1b00",
        danger:  "#f85149",
        "danger-bg": "#2d0d0d",
        ok:      "#3fb950",
        "ok-bg": "#0a1f0c",
      },
      fontFamily: {
        mono: ["'Fira Code'", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
