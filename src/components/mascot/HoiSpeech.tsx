import type { HTMLAttributes, ReactNode } from "react";
import { Hoi, type HoiMood, type HoiSize } from "./Hoi";

export interface HoiSpeechProps extends HTMLAttributes<HTMLDivElement> {
  mood?: HoiMood;
  size?: Extract<HoiSize, "sm" | "md" | "lg">;
  children: ReactNode;
  hideMascot?: boolean;
  /** 선택. 말풍선 안, 본문 아래에 구분선과 함께 보여 줄 보조 문구(예: 한계 고지, 요구사항 8.3). */
  footer?: ReactNode;
}

/**
 * 호이와 말풍선. 640px 미만은 세로(호이 위, 말풍선 아래), 이상은 가로 배치(요구사항 3.19).
 * 호이는 장식으로 숨기고, 말풍선 텍스트는 일반 텍스트라 스크린리더가 그대로 읽는다.
 */
export function HoiSpeech({
  mood = "guide",
  size = "md",
  children,
  hideMascot = false,
  footer,
  className = "",
  ...props
}: HoiSpeechProps) {
  return (
    <div
      role="group"
      aria-label="호이의 안내"
      {...props}
      className={`flex flex-col items-center gap-3 sm:flex-row sm:items-end ${className}`}
    >
      {!hideMascot && <Hoi mood={mood} size={size} decorative />}
      <div className="relative min-w-0 max-w-full rounded-3xl border border-line-strong bg-surface px-5 py-4 font-bold leading-relaxed text-ink shadow-warm sm:mb-2">
        {/* 꼬리: 모바일은 위쪽(호이 방향), sm 이상은 왼쪽 */}
        <span
          aria-hidden="true"
          className="absolute -top-2 left-1/2 h-4 w-4 -translate-x-1/2 rotate-45 border-l border-t border-line-strong bg-surface sm:-left-2 sm:bottom-4 sm:top-auto sm:translate-x-0 sm:border-b sm:border-t-0"
        />
        <div className="relative break-words">{children}</div>
        {footer && (
          <div className="relative mt-3 border-t border-line pt-3 text-sm font-normal leading-relaxed text-ink-subtle">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
