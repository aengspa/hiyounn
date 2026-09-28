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
          50: "#EEF1FC",
          100: "#E8ECFB",
          300: "#9DAEEF",
          500: "#4A62DE",
          600: "#2945D7",
          700: "#1F35B0",
          900: "#152578",
        },
        sev: {
          critical: "#C23B4B",
          high: "#B5590E",
          medium: "#A5690A",
          low: "#2568B3",
        },
      },
      fontFamily: {
        sans: [
          "Pretendard",
          "Apple SD Gothic Neo",
          "Noto Sans KR",
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
        "4xl": "1.5rem",
      },
      boxShadow: {
        warm: "0 1px 2px rgba(25, 38, 56, 0.04), 0 8px 20px rgba(25, 38, 56, 0.06)",
        press: "none",
      },
      keyframes: {
        "hoi-in": {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "hoi-in": "hoi-in 200ms ease-out both",
      },
    },
  },
  plugins: [],
};

export default config;
