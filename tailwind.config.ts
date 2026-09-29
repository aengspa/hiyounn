import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // 값의 원본은 globals.css `:root`(= src/lib/ui/tokens.ts WARM_TOKENS)다.
      // 기본은 CSS 변수로 참조한다. `/투명도` 수식어(예: bg-primary-soft/60)와 함께
      // 쓰는 키는 var()로는 투명도가 적용되지 않으므로 hex 값을 직접 쓴다.
      colors: {
        // 표면
        canvas: "var(--background)",
        "canvas-soft": "var(--background-soft)",
        surface: "var(--surface)",
        "surface-warm": "var(--surface-warm)",
        // 텍스트
        ink: "var(--text)",
        "ink-subtle": "var(--text-subtle)",
        "ink-muted": "var(--text-muted)",
        // 경계·포커스
        line: "var(--border)",
        "line-strong": "var(--border-strong)",
        "line-input": "var(--border-input)",
        focus: "var(--focus)",
        // 브랜드
        primary: "var(--primary)",
        "primary-hover": "var(--primary-hover)",
        "primary-soft": "#ffdfb8", // = --primary-soft. /60, /40 수식어와 함께 쓰여 hex 사용
        "primary-depth": "var(--primary-depth)",
        "primary-text": "var(--primary-text)",
        sun: "var(--sun)",
        "sun-soft": "var(--sun-soft)",
        crimson: "var(--crimson)",
        "crimson-soft": "var(--crimson-soft)",
        // 상태
        success: "var(--success)",
        "success-soft": "var(--success-soft)",
        danger: "var(--danger)",
        "danger-soft": "var(--danger-soft)",
        warning: "var(--warning)",
        "warning-soft": "var(--warning-soft)",
        info: "var(--info)",
        "info-soft": "var(--info-soft)",
        // 코드 패널
        code: "var(--code)",
        "code-text": "var(--code-text)",
        "code-muted": "var(--code-muted)",
        "code-focus": "var(--code-focus)",
        // 색상각 22°~33°, 명도 단조 감소. 텍스트에는 brand-800만 쓴다(500/600/700 금지).
        brand: {
          50: "#fff6ec",
          100: "#ffead3",
          200: "#ffdfb8",
          300: "#ffc38a",
          400: "#ffa45c",
          500: "#f58a36", // = --primary
          600: "#e97c2b", // = --primary-hover
          700: "#c8611a", // = --primary-depth
          800: "#9a4410", // = --primary-text
          900: "#6e300c",
        },
        // 장식 점·아이콘 채움용
        sev: {
          critical: "#b42f2f",
          high: "#c8611a",
          medium: "#8a5300",
          low: "#2f6aa3",
        },
      },
      fontFamily: {
        sans: [
          "Pretendard Variable",
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
        warm: "var(--shadow-sm)",
        "warm-lg": "var(--shadow-lg)",
        press: "0 3px 0 var(--primary-depth)",
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
