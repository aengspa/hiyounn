/**
 * 따뜻한 호이 디자인 토큰과 WCAG 2.1 대비 계산.
 *
 * - `WARM_TOKENS`의 키는 `globals.css` `:root`의 CSS 변수 이름에서 `--`를 뺀 값이다.
 *   두 곳의 값은 항상 같아야 하며 테스트가 이를 확인한다.
 * - 조정한 토큰은 `기준값 → 조정값 (측정 대비)`를 주석으로 남긴다(요구사항 1.2).
 * - React·DOM 의존이 없는 순수 모듈이다.
 */

export const WARM_TOKENS = {
  // 표면
  background: "#fff8ed",
  "background-soft": "#fff1cf",
  surface: "#ffffff",
  "surface-warm": "#fffaf2",

  // 브랜드
  primary: "#f58a36", // 텍스트 색으로 쓰지 않음. --text 대비 5.54
  "primary-hover": "#e97c2b", // #df7022 → #e97c2b (--text 대비 4.19 → 4.77)
  "primary-soft": "#ffdfb8", // 이 배경에는 --text-muted 금지
  sun: "#ffc857",
  "sun-soft": "#fff0b8",
  crimson: "#9e1b32",
  "crimson-soft": "#f9e7eb",

  // 상태
  success: "#1f7337", // #3fae5a → #1f7337 (--success-soft 대비 2.55 → 5.31)
  "success-soft": "#e8f7eb",
  danger: "#b42f2f", // #df4d4d → #b42f2f (--danger-soft 대비 3.57 → 5.59, 흰 글자 6.20)
  "danger-soft": "#fff0ee",
  warning: "#8a5300", // #e99b22 → #8a5300 (--warning-soft 대비 2.10 → 5.82)
  "warning-soft": "#fff5d9",
  info: "#2f6aa3", // #4a89c7 → #2f6aa3 (--info-soft 대비 3.38 → 5.18)
  "info-soft": "#edf6ff",

  // 텍스트
  text: "#3a2b20",
  "text-subtle": "#756354",
  "text-muted": "#7a6757", // #9a8879 → #7a6757 (cream 대비 3.22 → 5.10)

  // 경계·포커스
  border: "#eadbc8", // 장식용 구분선. 텍스트·입력 경계에 쓰지 않음
  "border-strong": "#d6bea3", // 카드 테두리 장식
  focus: "#9e1b32",

  // 추가 토큰(기준 25개 외)
  "primary-depth": "#c8611a", // Primary 버튼 하단 깊이 (brand-700)
  "primary-text": "#9a4410", // 브랜드색 텍스트 (brand-800)
  "border-input": "#967f6b", // 입력·체크박스 경계 (UI 경계 3:1)
  code: "#2a1d14", // 코드·diff·로그 패널 배경
  "code-text": "#fffaf2",
  "code-muted": "#c9b3a0",
  "code-focus": "#ffc857", // 코드 패널 안 포커스 링 (--focus는 대비 부족)
} as const;

export type TokenName = keyof typeof WARM_TOKENS;

/** 화면에서 실제로 쓰는 텍스트/배경 조합과 필요한 최소 대비 */
export interface ContrastPair {
  fg: TokenName;
  bg: TokenName;
  min: 4.5 | 3;
  use: string;
}

const HEX_RE = /^#?([0-9a-fA-F]{6})$/;

function parseHex(hex: string): [number, number, number] {
  const match = HEX_RE.exec(hex.trim());
  if (!match) {
    throw new Error(`6자리 hex 색이 아니에요: ${hex}`);
  }
  const value = match[1];
  return [
    parseInt(value.slice(0, 2), 16),
    parseInt(value.slice(2, 4), 16),
    parseInt(value.slice(4, 6), 16),
  ];
}

/** sRGB 채널(0~255)을 선형 값으로 변환 (WCAG 2.1) */
function linearize(channel: number): number {
  const c = channel / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

/** WCAG 2.1 상대 휘도. 0(검정) ~ 1(흰색) */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = parseHex(hex);
  return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b);
}

/** WCAG 2.1 대비율. 1 ~ 21, 인자 순서와 무관 */
export function contrastRatio(fgHex: string, bgHex: string): number {
  const a = relativeLuminance(fgHex);
  const b = relativeLuminance(bgHex);
  const lighter = Math.max(a, b);
  const darker = Math.min(a, b);
  return (lighter + 0.05) / (darker + 0.05);
}

const SURFACES = ["background", "background-soft", "surface", "surface-warm"] as const;

const SURFACE_LABEL: Record<(typeof SURFACES)[number], string> = {
  background: "크림 배경",
  "background-soft": "옅은 노랑 배경",
  surface: "흰 카드",
  "surface-warm": "따뜻한 카드",
};

function onSurfaces(fg: TokenName, min: 4.5 | 3, use: string): ContrastPair[] {
  return SURFACES.map((bg) => ({ fg, bg, min, use: `${use} · ${SURFACE_LABEL[bg]}` }));
}

const STATUS_PAIRS: ReadonlyArray<readonly [TokenName, TokenName, string]> = [
  ["success", "success-soft", "성공 상태"],
  ["danger", "danger-soft", "위험 상태"],
  ["warning", "warning-soft", "주의 상태"],
  ["info", "info-soft", "안내 상태"],
  ["crimson", "crimson-soft", "강조(크림슨)"],
];

export const CONTRAST_PAIRS: readonly ContrastPair[] = [
  // 본문·보조 텍스트 × 네 표면
  ...onSurfaces("text", 4.5, "본문 텍스트"),
  ...onSurfaces("text-subtle", 4.5, "보조 텍스트"),
  ...onSurfaces("text-muted", 4.5, "흐린 텍스트"),

  // 상태색 × 짝 soft 배경, cream, white
  ...STATUS_PAIRS.flatMap(([fg, soft, use]): ContrastPair[] => [
    { fg, bg: soft, min: 4.5, use: `${use} 배지 텍스트` },
    { fg, bg: "background", min: 4.5, use: `${use} 텍스트 · 크림 배경` },
    { fg, bg: "surface", min: 4.5, use: `${use} 텍스트 · 흰 카드` },
  ]),

  // --text × 브랜드·노랑 배경
  { fg: "text", bg: "primary", min: 4.5, use: "Primary 버튼 기본" },
  { fg: "text", bg: "primary-hover", min: 4.5, use: "Primary 버튼 hover·pressed" },
  { fg: "text", bg: "sun", min: 4.5, use: "노랑 강조 배경 텍스트" },
  { fg: "text", bg: "sun-soft", min: 4.5, use: "옅은 노랑 배경 텍스트" },
  { fg: "text", bg: "primary-soft", min: 4.5, use: "활성 메뉴·ghost hover 텍스트" },

  // 브랜드색 텍스트
  { fg: "primary-text", bg: "background", min: 4.5, use: "브랜드 텍스트 · 크림 배경" },
  { fg: "primary-text", bg: "surface", min: 4.5, use: "브랜드 텍스트 · 흰 카드" },
  { fg: "primary-text", bg: "primary-soft", min: 4.5, use: "브랜드 텍스트 · 활성 메뉴" },

  // 포커스 링 × 네 표면 (UI 구성 요소 3:1)
  ...onSurfaces("focus", 3, "포커스 링"),

  // 입력 경계 (UI 구성 요소 3:1)
  { fg: "border-input", bg: "surface", min: 3, use: "입력 경계 · 흰 카드" },
  { fg: "border-input", bg: "background", min: 3, use: "입력 경계 · 크림 배경" },

  // 코드 패널
  { fg: "code-text", bg: "code", min: 4.5, use: "코드 패널 본문" },
  { fg: "code-muted", bg: "code", min: 4.5, use: "코드 패널 보조 텍스트" },
  { fg: "code-focus", bg: "code", min: 3, use: "코드 패널 포커스 링" },

  // 흰 글자 × danger 버튼
  { fg: "surface", bg: "danger", min: 4.5, use: "Danger 버튼 흰 글자" },
];
