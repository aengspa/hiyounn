import type { SVGProps } from "react";

export type HoiMood =
  | "welcome"
  | "guide"
  | "searching"
  | "thinking"
  | "concerned"
  | "cheer"
  | "celebrate"
  | "rest";

export type HoiSize = "sm" | "md" | "lg" | "xl";

const SIZE_CLASS: Record<HoiSize, string> = {
  sm: "h-12 w-12",
  md: "h-24 w-24",
  lg: "h-40 w-40",
  xl: "h-56 w-56",
};

const MOOD_LABEL: Record<HoiMood, string> = {
  welcome: "손을 흔들며 반기는 호이",
  guide: "안내할 곳을 가리키는 호이",
  searching: "돋보기로 살펴보는 호이",
  thinking: "차분히 생각하는 호이",
  concerned: "발견한 문제를 진지하게 살피는 호이",
  cheer: "힘내라고 응원하는 호이",
  celebrate: "두 팔을 들고 축하하는 호이",
  rest: "편안히 쉬고 있는 호이",
};

export interface HoiProps extends Omit<SVGProps<SVGSVGElement>, "title"> {
  mood?: HoiMood;
  size?: HoiSize;
  title?: string;
  decorative?: boolean;
}

/**
 * 사용자 제공 채팅 레퍼런스의 금빛 노란 호랑이를 바탕으로 직접 그린 인라인 SVG.
 * 외부 이미지나 이모지에 의존하지 않아 모든 상태에서 같은 호이를 유지한다.
 */
export function Hoi({
  mood = "welcome",
  size = "md",
  title,
  decorative = false,
  className = "",
  ...props
}: HoiProps) {
  const isRest = mood === "rest";
  const isConcerned = mood === "concerned";
  const isThinking = mood === "thinking";
  const isHappy = mood === "welcome" || mood === "cheer" || mood === "celebrate";
  const armsUp = mood === "celebrate";
  const leftWave = mood === "welcome";
  const rightGuide = mood === "guide";
  const label = title ?? MOOD_LABEL[mood];

  return (
    <svg
      viewBox="0 0 240 240"
      fill="none"
      className={`${SIZE_CLASS[size]} shrink-0 ${mood === "searching" ? "hoi-searching" : "hoi-enter"} ${className}`}
      role={decorative ? undefined : "img"}
      aria-label={decorative ? undefined : label}
      aria-hidden={decorative || undefined}
      focusable="false"
      {...props}
    >
      {!decorative && <title>{label}</title>}

      {/* 짧고 둥근 줄무늬 꼬리 */}
      <path
        d="M181 157c30-6 38 11 29 25-7 11-22 11-30 2"
        stroke="#4a3324"
        strokeWidth="18"
        strokeLinecap="round"
      />
      <path d="M202 162l-4 17M216 169l-7 14" stroke="#17130f" strokeWidth="6" strokeLinecap="round" />
      <path
        d="M181 157c30-6 38 11 29 25-7 11-22 11-30 2"
        stroke="#e8a51f"
        strokeWidth="11"
        strokeLinecap="round"
      />
      <path d="M202 160l-3 19M215 168l-7 15" stroke="#2b2119" strokeWidth="5" strokeLinecap="round" />

      {/* 귀 */}
      <circle cx="72" cy="52" r="25" fill="#4a3324" />
      <circle cx="168" cy="52" r="25" fill="#4a3324" />
      <circle cx="72" cy="52" r="18" fill="#e8a51f" />
      <circle cx="168" cy="52" r="18" fill="#e8a51f" />
      <circle cx="72" cy="53" r="9" fill="#f58e98" />
      <circle cx="168" cy="53" r="9" fill="#f58e98" />

      {/* 머리와 몸이 이어지는 포근한 실루엣 */}
      <path
        d="M120 34c-42 0-69 25-69 62 0 19 6 32 15 41-9 17-13 38-8 57 5 19 25 29 62 29s57-10 62-29c5-19 1-40-8-57 9-9 15-22 15-41 0-37-27-62-69-62z"
        fill="#4a3324"
      />
      <path
        d="M120 41c-37 0-62 21-62 55 0 20 8 32 18 40-9 16-14 36-9 54 4 16 22 25 53 25s49-9 53-25c5-18 0-38-9-54 10-8 18-20 18-40 0-34-25-55-62-55z"
        fill="#f3b72c"
      />
      <ellipse cx="120" cy="173" rx="35" ry="39" fill="#fffaf0" />

      {/* 이마·볼·몸 줄무늬 */}
      <path d="M104 48l8 25 8-29 8 29 9-25" stroke="#2b2119" strokeWidth="7" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M65 87l24 8M64 103l24 2M175 87l-24 8M176 103l-24 2" stroke="#2b2119" strokeWidth="7" strokeLinecap="round" />
      <path d="M69 151l20 8M67 169l18 5M171 151l-20 8M173 169l-18 5" stroke="#2b2119" strokeWidth="7" strokeLinecap="round" />

      {/* 짧고 통통한 팔 */}
      {armsUp ? (
        <>
          <path d="M76 156c-23-14-26-39-16-51" stroke="#4a3324" strokeWidth="22" strokeLinecap="round" />
          <path d="M164 156c23-14 26-39 16-51" stroke="#4a3324" strokeWidth="22" strokeLinecap="round" />
          <path d="M76 156c-20-13-22-34-15-47" stroke="#f3b72c" strokeWidth="14" strokeLinecap="round" />
          <path d="M164 156c20-13 22-34 15-47" stroke="#f3b72c" strokeWidth="14" strokeLinecap="round" />
          <circle cx="60" cy="105" r="10" fill="#f58e98" stroke="#4a3324" strokeWidth="5" />
          <circle cx="180" cy="105" r="10" fill="#f58e98" stroke="#4a3324" strokeWidth="5" />
        </>
      ) : (
        <>
          <path
            d={leftWave ? "M78 155c-23-9-33-29-25-45" : "M78 156c-18 7-22 23-14 34"}
            stroke="#4a3324"
            strokeWidth="22"
            strokeLinecap="round"
          />
          <path
            d={rightGuide ? "M162 156c24 3 38-5 48-16" : "M162 156c18 7 22 23 14 34"}
            stroke="#4a3324"
            strokeWidth="22"
            strokeLinecap="round"
          />
          <path
            d={leftWave ? "M78 155c-19-8-27-25-21-41" : "M78 156c-15 7-18 20-11 31"}
            stroke="#f3b72c"
            strokeWidth="14"
            strokeLinecap="round"
          />
          <path
            d={rightGuide ? "M162 156c21 3 33-4 44-14" : "M162 156c15 7 18 20 11 31"}
            stroke="#f3b72c"
            strokeWidth="14"
            strokeLinecap="round"
          />
          <circle cx={leftWave ? 56 : 66} cy={leftWave ? 111 : 188} r="9" fill="#f58e98" stroke="#4a3324" strokeWidth="5" />
          <circle cx={rightGuide ? 207 : 174} cy={rightGuide ? 141 : 188} r="9" fill="#f58e98" stroke="#4a3324" strokeWidth="5" />
        </>
      )}

      {/* 짧은 다리와 분홍 발바닥 */}
      <path d="M94 205c-5 10-5 19 1 23M146 205c5 10 5 19-1 23" stroke="#4a3324" strokeWidth="23" strokeLinecap="round" />
      <path d="M94 205c-4 10-4 18 1 21M146 205c4 10 4 18-1 21" stroke="#f3b72c" strokeWidth="15" strokeLinecap="round" />
      <ellipse cx="94" cy="226" rx="10" ry="7" fill="#f58e98" />
      <ellipse cx="146" cy="226" rx="10" ry="7" fill="#f58e98" />

      {/* 작은 눈과 표정 */}
      {isRest ? (
        <path d="M88 103c5 5 10 5 15 0M137 103c5 5 10 5 15 0" stroke="#211912" strokeWidth="5" strokeLinecap="round" />
      ) : (
        <>
          <ellipse cx="96" cy="102" rx="5" ry={isConcerned ? 4 : 6} fill="#211912" />
          <ellipse cx="144" cy="102" rx="5" ry={isConcerned ? 4 : 6} fill="#211912" />
        </>
      )}
      {isConcerned && <path d="M87 91l15-4M153 91l-15-4" stroke="#4a3324" strokeWidth="4" strokeLinecap="round" />}
      {isThinking && <path d="M86 91l13-2" stroke="#4a3324" strokeWidth="4" strokeLinecap="round" />}
      <path d="M113 112c4-4 10-4 14 0-1 6-4 9-7 9s-6-3-7-9z" fill="#3a281d" />
      <path d="M120 120v4M120 124c-6 0-9 4-10 8M120 124c6 0 9 4 10 8" stroke="#4a3324" strokeWidth="3.5" strokeLinecap="round" />
      {isHappy ? (
        <path d="M104 130c6 18 26 18 32 0-10 5-22 5-32 0z" fill="#a62b35" stroke="#4a3324" strokeWidth="4" strokeLinejoin="round" />
      ) : isConcerned ? (
        <path d="M110 136c6-6 14-6 20 0" stroke="#4a3324" strokeWidth="4" strokeLinecap="round" />
      ) : (
        <path d="M108 130c7 9 17 9 24 0" stroke="#4a3324" strokeWidth="4" strokeLinecap="round" />
      )}
      {isHappy && (
        <>
          <path d="M109 132l5 8 4-9M131 132l-5 8-4-9" fill="#fff" stroke="#fff" strokeWidth="2" strokeLinejoin="round" />
          <path d="M112 143c5-4 11-4 16 0" stroke="#f58e98" strokeWidth="3" strokeLinecap="round" />
        </>
      )}

      {/* 상태별 작은 도구/기호 */}
      {mood === "searching" && (
        <g transform="translate(158 104) rotate(-12)">
          <circle cx="20" cy="20" r="15" fill="#dff2ff" fillOpacity=".75" stroke="#4a3324" strokeWidth="6" />
          <path d="M31 31l18 18" stroke="#4a3324" strokeWidth="8" strokeLinecap="round" />
        </g>
      )}
      {mood === "thinking" && (
        <g fill="#9e1b32">
          <circle cx="172" cy="72" r="3" />
          <circle cx="184" cy="62" r="5" />
          <circle cx="200" cy="48" r="7" />
        </g>
      )}
      {mood === "cheer" && (
        <path d="M188 79l4 8 9 1-7 6 2 9-8-5-8 5 2-9-7-6 9-1 4-8z" fill="#ffc857" stroke="#4a3324" strokeWidth="3" strokeLinejoin="round" />
      )}
      {mood === "celebrate" && (
        <g strokeLinecap="round" strokeWidth="4">
          <path d="M40 75l-9-8M46 58l-4-12M200 75l9-8M194 58l4-12" stroke="#9e1b32" />
          <path d="M28 91l-13-2M212 91l13-2" stroke="#e28916" />
        </g>
      )}
    </svg>
  );
}
