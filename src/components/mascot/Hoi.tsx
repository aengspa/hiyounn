import type { ReactNode, SVGProps } from "react";
import type { HoiMood } from "@/lib/ui/presentation";
import { HoiImage } from "./HoiImage";

// HoiMood는 presentation.ts가 원본이다. 기존 import 경로(`@/components/mascot/Hoi`)를 유지하려고 다시 내보낸다.
export type { HoiMood } from "@/lib/ui/presentation";

export type HoiSize = "sm" | "md" | "lg" | "xl";

/** 크기별 정사각형 영역: sm 48px, md 96px, lg 160px, xl 224px (요구사항 3.8). */
export const HOI_SIZE_CLASS: Record<HoiSize, string> = {
  sm: "h-12 w-12",
  md: "h-24 w-24",
  lg: "h-40 w-40",
  xl: "h-56 w-56",
};

/** 이전 이름 호환용 별칭. */
export const SIZE_CLASS = HOI_SIZE_CLASS;

/** Mood별 한국어 접근성 라벨 (요구사항 3.18). */
export const HOI_MOOD_LABEL: Record<HoiMood, string> = {
  welcome: "손을 흔들며 반기는 호이",
  guide: "안내할 곳을 가리키는 호이",
  searching: "돋보기로 살펴보는 호이",
  thinking: "차분히 생각하는 호이",
  concerned: "발견한 문제를 진지하게 살피는 호이",
  cheer: "힘내라고 응원하는 호이",
  celebrate: "두 팔을 들고 축하하는 호이",
  rest: "편안히 쉬고 있는 호이",
};

/** 이전 이름 호환용 별칭. */
export const MOOD_LABEL = HOI_MOOD_LABEL;

export type HoiArmPose =
  | "wave" // 한 팔을 머리 옆 높이로 들고 흔듦
  | "point" // 한 팔을 수평으로 뻗음
  | "hold-magnifier" // 한 손에 돋보기
  | "chin" // 한 손을 턱에
  | "together" // 두 팔을 몸 앞으로 모음
  | "fist-up" // 주먹을 들어 올림
  | "both-up" // 두 팔 모두 위로
  | "down"; // 두 팔을 몸 쪽에 내림

export type HoiEyes = "dot" | "closed";
export type HoiMouth = "open" | "smile" | "flat";
export type HoiPropKind = "wave" | "magnifier" | "thought" | "star" | "confetti";

export interface HoiPose {
  arms: HoiArmPose;
  eyes: HoiEyes;
  mouth: HoiMouth;
  brows: boolean;
  props: readonly HoiPropKind[];
}

/** Mood별 자세 표 (설계 3-2). SVG 조각 함수가 이 표만 읽어 그린다. */
export const MOOD_POSE: Record<HoiMood, HoiPose> = {
  welcome: { arms: "wave", eyes: "dot", mouth: "open", brows: false, props: ["wave"] },
  guide: { arms: "point", eyes: "dot", mouth: "smile", brows: false, props: [] },
  searching: { arms: "hold-magnifier", eyes: "dot", mouth: "smile", brows: false, props: ["magnifier"] },
  thinking: { arms: "chin", eyes: "dot", mouth: "flat", brows: false, props: ["thought"] },
  concerned: { arms: "together", eyes: "dot", mouth: "flat", brows: true, props: [] },
  cheer: { arms: "fist-up", eyes: "dot", mouth: "open", brows: false, props: ["star"] },
  celebrate: { arms: "both-up", eyes: "dot", mouth: "open", brows: false, props: ["confetti"] },
  rest: { arms: "down", eyes: "closed", mouth: "smile", brows: false, props: [] },
};

export interface HoiProps extends Omit<SVGProps<SVGSVGElement>, "title"> {
  mood?: HoiMood;
  size?: HoiSize;
  title?: string;
  decorative?: boolean;
  /** 선택. `public/hoi/` 아래 PNG(`/hoi/…png`)일 때만 이미지를 쓰고, 그 외에는 SVG를 그린다. */
  src?: string;
}

/**
 * 내부 PNG 경로만 허용한다: `/hoi/`로 시작, `.png`로 끝, `//`·`..`·`:` 없음 (요구사항 3.3).
 * 조건을 벗어나면 `null`을 돌려주어 인라인 SVG를 쓰게 한다.
 */
export function resolveHoiImageSrc(src: string | null | undefined): string | null {
  if (typeof src !== "string") return null;
  if (!src.startsWith("/hoi/") || !src.endsWith(".png")) return null;
  if (src.includes("//") || src.includes("..") || src.includes(":")) return null;
  return src;
}

// ─────────────────────────────────────────────────────────────
// 그림 재료
// ─────────────────────────────────────────────────────────────

const C = {
  body: "#F5B82E",
  outline: "#3B2414",
  stripe: "#1E1510",
  belly: "#FFFDF6",
  pad: "#F28B9B",
  padEdge: "#C8465A",
  mouth: "#C8323C",
  tongue: "#F07F8F",
  nose: "#2B1A10",
  white: "#FFFFFF",
  sun: "#FFC857",
  orange: "#F58A36",
  crimson: "#9E1B32",
  lens: "#E3F3FF",
  handle: "#8A5A33",
} as const;

const OUTLINE_W = 5;
/** 팔: 채움 15 + 양쪽 외곽선 5 */
const ARM_FILL_W = 15;
const ARM_OUTLINE_W = ARM_FILL_W + OUTLINE_W * 2;
/** 어깨 이음새를 몸 색으로 덮는 원 반지름(팔 외곽선 반폭과 같음) */
const SHOULDER_PATCH_R = ARM_OUTLINE_W / 2;

type Point = readonly [number, number];

interface ArmSpec {
  /** 어깨(몸 안쪽)에서 손끝까지의 중심선 */
  d: string;
  shoulder: Point;
  hand: Point;
  paw: "pad" | "fist";
}

const SHOULDER_L: Point = [70, 127];
const SHOULDER_R: Point = [130, 127];

const DOWN_L: ArmSpec = { d: "M70 127 C69 139 72 148 80 153", shoulder: SHOULDER_L, hand: [80, 153], paw: "pad" };
const DOWN_R: ArmSpec = { d: "M130 127 C131 139 128 148 120 153", shoulder: SHOULDER_R, hand: [120, 153], paw: "pad" };

/** 그리는 순서대로 나열한다(뒤에 오는 팔이 위에 그려진다). */
const ARM_SHAPES: Record<HoiArmPose, readonly ArmSpec[]> = {
  wave: [DOWN_L, { d: "M130 127 C162 128 182 108 180 64", shoulder: SHOULDER_R, hand: [180, 64], paw: "pad" }],
  point: [DOWN_L, { d: "M130 127 C150 126 168 122 184 119", shoulder: SHOULDER_R, hand: [184, 119], paw: "pad" }],
  "hold-magnifier": [
    DOWN_L,
    { d: "M130 127 C146 128 160 126 164 114", shoulder: SHOULDER_R, hand: [164, 114], paw: "fist" },
  ],
  chin: [DOWN_R, { d: "M70 127 C84 142 106 140 112 120", shoulder: SHOULDER_L, hand: [112, 120], paw: "pad" }],
  together: [
    { d: "M70 127 C72 141 81 149 92 149", shoulder: SHOULDER_L, hand: [92, 149], paw: "pad" },
    { d: "M130 127 C128 141 119 149 108 149", shoulder: SHOULDER_R, hand: [108, 149], paw: "pad" },
  ],
  "fist-up": [
    { d: "M70 127 C73 140 82 146 92 142", shoulder: SHOULDER_L, hand: [92, 142], paw: "fist" },
    { d: "M130 127 C162 128 182 106 178 72", shoulder: SHOULDER_R, hand: [178, 72], paw: "fist" },
  ],
  "both-up": [
    { d: "M70 127 C36 128 16 104 18 54", shoulder: SHOULDER_L, hand: [18, 54], paw: "pad" },
    { d: "M130 127 C164 128 184 104 182 54", shoulder: SHOULDER_R, hand: [182, 54], paw: "pad" },
  ],
  down: [DOWN_L, DOWN_R],
};

function r1(v: number): number {
  return Math.round(v * 10) / 10;
}

/** 끝이 둥근 5각 별 경로 */
function starPath(cx: number, cy: number, outer: number, inner: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 10; i += 1) {
    const r = i % 2 === 0 ? outer : inner;
    const a = -Math.PI / 2 + (i * Math.PI) / 5;
    pts.push(`${r1(cx + r * Math.cos(a))} ${r1(cy + r * Math.sin(a))}`);
  }
  return `M${pts.join(" L")} Z`;
}

function Arm({ spec }: { spec: ArmSpec }) {
  const [sx, sy] = spec.shoulder;
  const [hx, hy] = spec.hand;
  return (
    <g>
      <path d={spec.d} stroke={C.outline} strokeWidth={ARM_OUTLINE_W} strokeLinecap="round" strokeLinejoin="round" />
      {/* 어깨 쪽 외곽선 끝을 몸 색으로 덮어 팔이 몸에서 자연스럽게 이어지게 한다 */}
      <circle cx={sx} cy={sy} r={SHOULDER_PATCH_R} fill={C.body} />
      <path d={spec.d} stroke={C.body} strokeWidth={ARM_FILL_W} strokeLinecap="round" strokeLinejoin="round" />
      {spec.paw === "pad" ? (
        <circle cx={hx} cy={hy} r={5} fill={C.pad} stroke={C.padEdge} strokeWidth={1.6} />
      ) : (
        <path
          d={`M${hx - 7} ${hy - 1} q3.5 -4 7 0 q3.5 -4 7 0`}
          stroke={C.outline}
          strokeWidth={2.6}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </g>
  );
}

function Foot({ cx }: { cx: number }) {
  return (
    <g>
      <ellipse cx={cx} cy={180} rx={15.5} ry={12.5} fill={C.body} stroke={C.outline} strokeWidth={OUTLINE_W} />
      <ellipse cx={cx} cy={184} rx={6.8} ry={5} fill={C.pad} stroke={C.padEdge} strokeWidth={1.6} />
      <g fill={C.pad} stroke={C.padEdge} strokeWidth={1.2}>
        <circle cx={cx - 6.5} cy={175.5} r={2.2} />
        <circle cx={cx} cy={173.5} r={2.2} />
        <circle cx={cx + 6.5} cy={175.5} r={2.2} />
      </g>
    </g>
  );
}

// 머리(폭 128)와 통통한 몸이 목의 얕은 들어감만 두고 하나로 이어지는 실루엣
const BODY_PATH =
  "M100 30 C138 30 164 48 164 78 C164 100 152 112 144 118 C152 130 156 150 152 166 " +
  "C148 180 128 184 100 184 C72 184 52 180 48 166 C44 150 48 130 56 118 " +
  "C48 112 36 100 36 78 C36 48 62 30 100 30 Z";

const TAIL_PATH = "M140 168 C162 170 178 162 180 144";

// 끝이 둥글고 가늘어지는 줄무늬
const STRIPE_PATHS = [
  // 이마 3개(가운데가 가장 김)
  "M93 31 C94 43 97 53 100 58 C103 53 106 43 107 31 Z",
  "M78 33.5 C81 41 84 46 88 50 C89 44 88.5 38 87 31.5 Z",
  "M122 33.5 C119 41 116 46 112 50 C111 44 111.5 38 113 31.5 Z",
  // 왼쪽 볼 2개
  "M36 74 C44 75 50 77 55 80.5 C50 82.5 44 83.5 36.5 84 Z",
  "M37.5 90 C44.5 90.5 49.5 92 53.5 94.5 C49.5 96.5 44.5 97.5 39.5 98.5 Z",
  // 오른쪽 볼 2개
  "M164 74 C156 75 150 77 145 80.5 C150 82.5 156 83.5 163.5 84 Z",
  "M162.5 90 C155.5 90.5 150.5 92 146.5 94.5 C150.5 96.5 155.5 97.5 160.5 98.5 Z",
  // 왼쪽 몸 옆 2개
  "M47.5 137 C52.5 138.5 56 140.5 58.5 143.5 C55 145.5 51.5 146.5 47 147.5 Z",
  "M46.5 153 C51.5 154.5 55 156.5 57.5 159.5 C54 161.5 50.5 162.5 47 163.5 Z",
  // 오른쪽 몸 옆 2개
  "M152.5 137 C147.5 138.5 144 140.5 141.5 143.5 C145 145.5 148.5 146.5 153 147.5 Z",
  "M153.5 153 C148.5 154.5 145 156.5 142.5 159.5 C146 161.5 149.5 162.5 153 163.5 Z",
];

function Eyes({ kind }: { kind: HoiEyes }) {
  return (
    <g data-part="eyes" data-kind={kind}>
      {kind === "closed" ? (
        <path
          d="M71 77 Q78 83.5 85 77 M115 77 Q122 83.5 129 77"
          stroke={C.stripe}
          strokeWidth={3.6}
          strokeLinecap="round"
        />
      ) : (
        <>
          <ellipse cx={78} cy={79} rx={5} ry={6} fill={C.stripe} />
          <ellipse cx={122} cy={79} rx={5} ry={6} fill={C.stripe} />
          <circle cx={79.8} cy={76.6} r={1.7} fill={C.white} />
          <circle cx={123.8} cy={76.6} r={1.7} fill={C.white} />
        </>
      )}
    </g>
  );
}

function Mouth({ kind }: { kind: HoiMouth }) {
  const philtrum = (
    <path d={`M100 94.5 V${kind === "open" ? 100.5 : kind === "flat" ? 100 : 98.5}`} stroke={C.outline} strokeWidth={3} strokeLinecap="round" />
  );
  if (kind === "open") {
    const lip = "M87 98.5 Q100 103.5 113 98.5 Q111.5 114 100 115 Q88.5 114 87 98.5 Z";
    return (
      <g data-part="mouth" data-kind="open">
        <path d={lip} fill={C.mouth} />
        <path d="M93 111.5 Q100 106.5 107 111.5 Q104 114.6 100 114.8 Q96 114.6 93 111.5 Z" fill={C.tongue} />
        <g data-part="fangs" fill={C.white} stroke={C.white} strokeWidth={1.2} strokeLinejoin="round">
          <path d="M90.5 99.8 L96.5 101 L93.8 106 Z" />
          <path d="M109.5 99.8 L103.5 101 L106.2 106 Z" />
        </g>
        <path d={lip} stroke={C.outline} strokeWidth={3} strokeLinejoin="round" />
        {philtrum}
      </g>
    );
  }
  if (kind === "flat") {
    return (
      <g data-part="mouth" data-kind="flat">
        {philtrum}
        <path d="M90 101.5 Q100 99 110 101.5" stroke={C.outline} strokeWidth={3.2} strokeLinecap="round" />
      </g>
    );
  }
  return (
    <g data-part="mouth" data-kind="smile">
      {philtrum}
      <path
        d="M100 98.5 Q95 104 88.5 100 M100 98.5 Q105 104 111.5 100"
        stroke={C.outline}
        strokeWidth={3.2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </g>
  );
}

function PropWave() {
  return (
    <g data-part="prop-wave" stroke={C.outline} strokeWidth={3.5} strokeLinecap="round">
      <path d="M182 42 A22 22 0 0 1 200 60" />
      <path d="M193 38 A30 30 0 0 1 205 51" />
    </g>
  );
}

/** 애니메이션 그룹에는 transform 속성을 두지 않는다(CSS transform과 충돌 방지). */
function PropMagnifier({ animated }: { animated: boolean }) {
  return (
    <g data-part="prop-magnifier" className={animated ? "hoi-search-prop" : undefined}>
      <path d="M158.5 122 L175 98.4" stroke={C.outline} strokeWidth={10} strokeLinecap="round" />
      <path d="M158.5 122 L175 98.4" stroke={C.handle} strokeWidth={4.5} strokeLinecap="round" />
      <circle cx={183.5} cy={86} r={15} fill={C.lens} fillOpacity={0.8} stroke={C.outline} strokeWidth={OUTLINE_W} />
      <path d="M175 81 Q177.5 75.5 183.5 74.5" stroke={C.white} strokeWidth={3} strokeLinecap="round" />
    </g>
  );
}

function PropThought() {
  return (
    <g data-part="prop-thought" fill={C.belly} stroke={C.outline} strokeWidth={2.6}>
      <circle cx={166} cy={48} r={3.5} />
      <circle cx={178} cy={34} r={5} />
      <circle cx={194} cy={17} r={7} />
    </g>
  );
}

function PropStar() {
  return (
    <g data-part="prop-star">
      <path d={starPath(196, 44, 10.5, 4.8)} fill={C.sun} stroke={C.outline} strokeWidth={3} strokeLinejoin="round" />
    </g>
  );
}

function PropConfetti() {
  return (
    <g data-part="prop-confetti">
      <g stroke={C.outline} strokeWidth={2.6} strokeLinejoin="round">
        <path d={starPath(100, 6, 9, 4.2)} fill={C.sun} />
        <path d={starPath(30, 16, 6.5, 3)} fill={C.sun} />
        <path d={starPath(172, 18, 6, 2.8)} fill={C.sun} />
      </g>
      <rect x={60} y={2} width={8} height={4.5} rx={1.5} fill={C.orange} transform="rotate(-25 64 4.25)" />
      <rect x={134} y={4} width={8} height={4.5} rx={1.5} fill={C.crimson} transform="rotate(30 138 6.25)" />
      <circle cx={10} cy={34} r={3.2} fill={C.crimson} />
      <circle cx={196} cy={34} r={3.2} fill={C.orange} />
    </g>
  );
}

function PropFor({ kind, mood }: { kind: HoiPropKind; mood: HoiMood }) {
  switch (kind) {
    case "wave":
      return <PropWave />;
    case "magnifier":
      return <PropMagnifier animated={mood === "searching"} />;
    case "thought":
      return <PropThought />;
    case "star":
      return <PropStar />;
    case "confetti":
      return <PropConfetti />;
  }
}

interface HoiSvgProps extends Omit<HoiProps, "src"> {
  mood: HoiMood;
  size: HoiSize;
}

/**
 * 사용자 레퍼런스(고려대 호이: 2D 플랫, 통통한 금빛 노랑 호랑이)를 바탕으로 직접 그린 인라인 SVG.
 * 외부 이미지·이모지에 의존하지 않는다. 훅이 없어 서버 컴포넌트에서도 쓸 수 있다.
 */
function HoiSvg({ mood, size, title, decorative = false, className = "", ...props }: HoiSvgProps) {
  const pose = MOOD_POSE[mood];
  const label = title ?? HOI_MOOD_LABEL[mood];
  // 돋보기는 손이 잡은 것처럼 보이도록 팔 아래에, 나머지 소품은 맨 위에 그린다.
  const behindArmProps = pose.props.filter((p) => p === "magnifier");
  const frontProps = pose.props.filter((p) => p !== "magnifier");
  const a11y = decorative
    ? { "aria-hidden": "true" as const }
    : { role: "img", "aria-label": label };

  return (
    <svg
      {...props}
      viewBox="0 0 200 200"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`${HOI_SIZE_CLASS[size]} shrink-0 hoi-enter ${className}`.trim()}
      focusable="false"
      data-mood={mood}
      {...a11y}
    >
      {!decorative && <title>{label}</title>}

      {/* 소품이 들어갈 여백을 위해 캐릭터 전체를 0.9배로 둔다 */}
      <g transform="translate(10 9) scale(0.9)">
        <g data-part="tail">
          <path d={TAIL_PATH} stroke={C.outline} strokeWidth={20} strokeLinecap="round" />
          <path d={TAIL_PATH} stroke={C.body} strokeWidth={10} strokeLinecap="round" />
          <path d="M168.5 157.4 L174.3 164.2 M173.9 149.7 L182.3 153.1" stroke={C.stripe} strokeWidth={4} strokeLinecap="round" />
        </g>

        <g data-part="ears">
          <circle cx={58} cy={34} r={16} fill={C.body} stroke={C.outline} strokeWidth={OUTLINE_W} />
          <circle cx={142} cy={34} r={16} fill={C.body} stroke={C.outline} strokeWidth={OUTLINE_W} />
          <circle cx={59} cy={34} r={7.5} fill={C.pad} />
          <circle cx={141} cy={34} r={7.5} fill={C.pad} />
        </g>

        <g data-part="body">
          <path d={BODY_PATH} fill={C.body} stroke={C.outline} strokeWidth={OUTLINE_W} strokeLinejoin="round" />
        </g>

        <g data-part="belly">
          <ellipse cx={100} cy={154} rx={28} ry={27} fill={C.belly} />
        </g>

        <g data-part="stripes" fill={C.stripe}>
          {STRIPE_PATHS.map((d) => (
            <path key={d} d={d} />
          ))}
        </g>

        <g data-part="blush" fill={C.pad} opacity={0.55}>
          <ellipse cx={64} cy={93} rx={7} ry={4} />
          <ellipse cx={136} cy={93} rx={7} ry={4} />
        </g>

        <g data-part="legs">
          <Foot cx={74} />
          <Foot cx={126} />
        </g>

        {behindArmProps.map((kind) => (
          <PropFor key={kind} kind={kind} mood={mood} />
        ))}

        <g data-part="arms" data-pose={pose.arms}>
          {ARM_SHAPES[pose.arms].map((spec) => (
            <Arm key={spec.d} spec={spec} />
          ))}
        </g>

        <Eyes kind={pose.eyes} />

        {pose.brows && (
          <g data-part="brows" stroke={C.outline} strokeWidth={3.6} strokeLinecap="round">
            <path d="M70 69 Q78 65.5 86 66" />
            <path d="M130 69 Q122 65.5 114 66" />
          </g>
        )}

        <g data-part="nose">
          <path d="M92.5 87 Q100 84 107.5 87 Q106.5 93 100 95 Q93.5 93 92.5 87 Z" fill={C.nose} />
        </g>

        <Mouth kind={pose.mouth} />

        {frontProps.map((kind) => (
          <PropFor key={kind} kind={kind} mood={mood} />
        ))}
      </g>
    </svg>
  );
}

/**
 * 호이 마스코트. 기본은 인라인 SVG이고, `src`가 검증된 내부 PNG 경로일 때만 이미지를 쓴다.
 * 이미지가 실패하면 같은 크기·접근성의 SVG로 대체한다(요구사항 3.4, 3.5).
 */
export function Hoi({ mood = "welcome", size = "md", title, decorative = false, className = "", src, ...props }: HoiProps) {
  const svg: ReactNode = (
    <HoiSvg mood={mood} size={size} title={title} decorative={decorative} className={className} {...props} />
  );
  const imageSrc = resolveHoiImageSrc(src);
  if (!imageSrc) return svg;

  return (
    <HoiImage
      src={imageSrc}
      alt={title ?? HOI_MOOD_LABEL[mood]}
      decorative={decorative}
      className={`${HOI_SIZE_CLASS[size]} shrink-0 object-contain hoi-enter ${className}`.trim()}
      fallback={svg}
    />
  );
}
