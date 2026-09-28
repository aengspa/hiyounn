import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "var(--background)",
        "canvas-soft": "var(--background-soft)",
        surface: "var(--surface)",
        "surface-warm": "var(--surface-warm)",
        ink: "var(--text)",
        "ink-subtle": "var(--text-subtle)",
        "ink-muted": "var(--text-muted)",
        line: "var(--border)",
        "line-strong": "var(--border-strong)",
        primary: "var(--primary)",
        "primary-hover": "var(--primary-hover)",
        "primary-soft": "var(--primary-soft)",
        sun: "var(--sun)",
        "sun-soft": "var(--sun-soft)",
        crimson: "var(--crimson)",
        "crimson-soft": "var(--crimson-soft)",
        success: "var(--success)",
        "success-soft": "var(--success-soft)",
        danger: "var(--danger)",
        "danger-soft": "var(--danger-soft)",
        warning: "var(--warning)",
        "warning-soft": "var(--warning-soft)",
        info: "var(--info)",
        "info-soft": "var(--info-soft)",
        code: "var(--code)",
        brand: {
          50: "#fff6ea",
          100: "#ffead0",
          300: "#f6b273",
          500: "#d6651d",
          600: "#b84a12",
          700: "#92380b",
          900: "#58220a",
        },
        sev: {
          critical: "#b83232",
          high: "#b84a12",
          medium: "#9a5b08",
          low: "#27699e",
        },
      },
      fontFamily: {
        sans: [
          "Pretendard",
          "Apple SD Gothic Neo",
          "Noto Sans KR",
          "ui-rounded",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      borderRadius: {
        "4xl": "2rem",
      },
      boxShadow: {
        warm: "0 12px 30px rgba(116, 67, 28, 0.10)",
        press: "0 4px 0 rgba(112, 54, 16, 0.28)",
      },
      keyframes: {
        "hoi-in": {
          "0%": { opacity: "0", transform: "translateY(8px) scale(.98)" },
          "100%": { opacity: "1", transform: "translateY(0) scale(1)" },
        },
      },
      animation: {
        "hoi-in": "hoi-in 260ms cubic-bezier(.2,.8,.2,1) both",
      },
    },
  },
  plugins: [],
};

export default config;
